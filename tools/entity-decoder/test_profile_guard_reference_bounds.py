"""Generic declaration limits; no application offsets, labels or identities."""
import copy
import json
import unittest

from relations import GuardedRelations, InvalidBinding


def profile(fields=1, references=1, distinct=1, schema=4):
    guards = [dict(address=4096 + 8*i, bytes_hex='01000000') for i in range(distinct)]
    result = dict(schema=f'overwatch-decoder.field-profile/{schema}', target=dict(pid=123,
        creation_file_time=456, executable_sha256='ab'*32, architecture='x64', image_name='fixture.exe'),
        guards=[], fields=[dict(name=f'value_{i}', type='i32', address=8192 + 4*i, guards=[])
                          for i in range(fields)])
    for i in range(references):
        result['fields'][i % fields]['guards'].append(copy.deepcopy(guards[i % distinct]))
    return result


def decoder(value):
    return GuardedRelations(json.dumps(value,separators=(',', ':')).encode(), allow_profile4=True)


class ProfileGuardReferenceBoundsTests(unittest.TestCase):
    def test_seven_and_eight_group_sized_profiles_keep_field_specific_dependencies(self):
        for fields,references in ((93,1075),(105,1211),(139,1623)):
            with self.subTest(fields=fields):
                value=profile(fields,references,distinct=200)
                parsed=decoder(value)
                self.assertEqual(len(parsed.fields),fields)
                self.assertEqual(len(parsed.guards),200)
                self.assertEqual(sum(len(f['guards']) for f in parsed.fields.values()),references)
                for name,field in parsed.fields.items():
                    expected=[parsed.guards.index(g) for g in field['guards']]
                    self.assertEqual(parsed.guard_ids[name],list(dict.fromkeys(expected)))
                    self.assertLess(len(parsed.guard_ids[name]),len(parsed.guards))

    def test_1920_references_admitted_but_1921_rejected_before_dedup(self):
        self.assertEqual(len(decoder(profile(160,1920)).guards),1)
        with self.assertRaisesRegex(InvalidBinding,'profile_guard_reference_bounds'):
            decoder(profile(160,1921))

    def test_global_and_field_references_share_one_declaration_budget(self):
        value=profile(160,1920)
        value['guards']=[value['fields'][0]['guards'].pop()]
        decoder(value)
        value['guards'].append(copy.deepcopy(value['guards'][0]))
        with self.assertRaisesRegex(InvalidBinding,'profile_guard_reference_bounds'):
            decoder(value)

    def test_v1_declaration_limit_is_unchanged(self):
        decoder(profile(128,256,schema=1))
        with self.assertRaisesRegex(InvalidBinding,'profile_guard_reference_bounds'):
            decoder(profile(128,257,schema=1))

    def test_expanded_field_and_unchanged_distinct_guard_limits(self):
        self.assertEqual(len(decoder(profile(128,256,256)).guards),256)
        for value in (profile(161,161),profile(128,257,257)):
            with self.subTest(fields=len(value['fields'])),self.assertRaisesRegex(InvalidBinding,'profile_bounds'):
                decoder(value)

    def test_profile_byte_limit_and_schema_optin_are_unchanged(self):
        raw=json.dumps(profile()).encode()
        with self.assertRaisesRegex(InvalidBinding,'unsupported_profile_schema'):
            GuardedRelations(raw)
        padded=raw+b' '*(256*1024-len(raw))
        GuardedRelations(padded,allow_profile4=True)
        with self.assertRaisesRegex(InvalidBinding,'invalid_profile'):
            GuardedRelations(padded+b' ',allow_profile4=True)


if __name__=='__main__':unittest.main()
