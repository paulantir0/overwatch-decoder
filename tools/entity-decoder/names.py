"""Research-only account name projection from a verified native name route.

The caller must verify the acquisition recipe and recording, as for relations.py.
A text value or field label alone does not establish a participant name.
"""
import hashlib
import re
import unicodedata

from relations import GuardedRelations, InvalidBinding


class GuardedNames:
    def __init__(self, raw_profile: bytes):
        self.relations = GuardedRelations(raw_profile)

    def project(self, frame):
        relations = self.relations.project(frame)
        result = {key: value for key, value in relations.items() if key != 'relations'}
        result.update(schema='overwatch-decoder.guarded-account-names/1', privacy='private', names=[])
        for relation in relations['relations']:
            prefix = relation['controller_prefix']
            row = dict(controller_object_key=relation['controller_object_key'],
                       body_object_key=relation['body_object_key'], status='unknown', reason=None,
                       private_name=None, display_name=None, evidence=[])
            try:
                if row['controller_object_key'] is None:
                    raise InvalidBinding(relation['reason'] or 'controller_unknown')
                account = [self.relations._observed(
                    prefix + f'_part36_0000_account_word{i}_candidate_i32', frame) for i in range(4)]
                if any(word['address'] != account[0]['address'] + 4 * i for i, word in enumerate(account)):
                    raise InvalidBinding('noncontiguous_account_token')
                pattern = re.compile(re.escape(prefix) + r'_name_(\d{4})_byte_(\d{4})_value\Z')
                declared = []
                for name in self.relations.fields:
                    match = pattern.fullmatch(name)
                    if match:
                        declared.append((int(match[1]), int(match[2]), name))
                declared.sort()
                if (not 1 <= len(declared) <= 64
                        or [(row_index, byte_index) for row_index, byte_index, _ in declared]
                        != [(0, i) for i in range(len(declared))]):
                    raise InvalidBinding('invalid_name_byte_declaration')
                samples = [self.relations.sample_scalar(name, frame, 'u8') for _, _, name in declared]
                if any(sample['address'] != samples[0]['address'] + i for i, sample in enumerate(samples)):
                    raise InvalidBinding('noncontiguous_name_bytes')
                raw = bytes(sample['value'] for sample in samples)
                if 0 not in raw:
                    raise InvalidBinding('unterminated_name')
                raw_name = raw[:raw.index(0)]
                try:
                    name = raw_name.decode('utf-8', errors='strict')
                except UnicodeDecodeError as error:
                    raise InvalidBinding('invalid_name_utf8') from error
                if not name or any(unicodedata.category(char).startswith('C') for char in name):
                    raise InvalidBinding('empty_or_control_name')
                row.update(status='observed', private_name=name,
                           display_name=re.sub(r'#[0-9]+\Z', '', name),
                           display_transform='remove_terminal_numeric_discriminator',
                           name_bytes_sha256=hashlib.sha256(raw_name).hexdigest(),
                           evidence=[{key: sample[key] for key in (
                               'field', 'read_start_ticks', 'read_end_ticks')}
                               for sample in account + samples])
            except InvalidBinding as error:
                row['reason'] = str(error)
            result['names'].append(row)
        return result
