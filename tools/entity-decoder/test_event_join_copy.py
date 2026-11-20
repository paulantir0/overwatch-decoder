"""Public copy ownership survives the existing JSON fast-copy helper."""
import copy
import unittest
from event_entity_join import EventEntityJoin
from event_join_stream import EventJoinStream


def scope():
    return dict(target=dict(pid=1,creation_file_time=2,executable_sha256='a'*64,
        image_name='fixture',architecture='x64'),world_epoch='w',clock_id='qpc',frequency=1000)


def pair(context,tick,key=1,hero='fixture'):
    observation=dict(scope=context,body_key_u32=key,observed_ticks=tick,valid_until_ticks=1000,
        status='observed',body_lifetime='life',entity_id='entity',controller_id='controller',
        hero=hero,relation='enemy',provenance={'frame':str(tick)})
    proof=dict(scope=context,body_key_u32=key,body_lifetime='life',entity_id='entity',
        controller_id='controller',valid_from_ticks=0,valid_until_ticks=1000,provenance={'proof':'fixture'})
    return observation,[proof]


def event(context,tick,payload=None):
    return dict(event=dict(scope=context,body_key_u32=1,qpc_ticks=tick,provenance={'event':str(tick)}),
        payload={}if payload is None else payload)


class CustomList(list):
    copies=0
    def __deepcopy__(self,memo):
        type(self).copies+=1
        result=type(self)();memo[id(self)]=result
        result.extend(copy.deepcopy(value,memo)for value in self)
        return result


class EventJoinCopyTests(unittest.TestCase):
    def test_observation_proof_input_and_public_result_graphs_are_detached(self):
        context=scope();observation,proofs=pair(context,10);query=event(copy.deepcopy(context),20)['event']
        join=EventEntityJoin(maximum_age_ticks=100);join.observe_many([(observation,proofs)])
        expected=join.join(query);self.assertIsNotNone(expected)
        observation['hero']='caller';observation['provenance']['frame']='caller'
        proofs[0]['provenance']['proof']='caller';context['target']['pid']=999
        self.assertEqual(join.join(query),expected)
        result=join.join(query);result['scope']['target']['pid']=888
        result['proof_provenance'][0].clear();result['observation_provenance'].clear()
        self.assertEqual(join.join(query),expected)

    def test_pending_payload_aliases_detach_and_previous_results_stay_stable(self):
        context=scope();stream=EventJoinStream(scope=context,sources=['a','b'],maximum_age_ticks=100)
        shared={'items':[1,{'value':2}]};wrapper=event(context,10,{'left':shared,'right':shared})
        self.assertEqual(stream.submit('b',10,events=[wrapper]),[])
        shared['items'][1]['value']=999
        first=stream.submit('a',10,observations=[pair(context,10)])[0]
        self.assertEqual(first['payload']['left']['items'],[1,{'value':2}])
        self.assertIs(first['payload']['left'],first['payload']['right'])
        first['payload']['left']['items'].clear();first['label']['scope']['target']['pid']=999
        first['label']['proof_provenance'][0].clear();saved=copy.deepcopy(first)
        stream.submit('a',20,observations=[pair(context,20)])
        second=stream.submit('b',20,events=[event(context,20)])[0]
        self.assertEqual(second['label']['scope']['target']['pid'],1)
        self.assertEqual(first,saved)

    def test_custom_container_copy_protocol_remains_a_fallback(self):
        CustomList.copies=0;context=scope();stream=EventJoinStream(scope=context,sources=['a','b'],maximum_age_ticks=100)
        shared=CustomList([{'values':[1,2]}]);wrapper=event(context,10,{'left':shared,'right':shared})
        stream.submit('b',10,events=[wrapper]);self.assertGreater(CustomList.copies,0)
        shared[0]['values'].append(999)
        result=stream.abort('deadline')[0]
        self.assertIs(type(result['payload']['left']),CustomList)
        self.assertIs(result['payload']['left'],result['payload']['right'])
        self.assertEqual(result['payload']['left'],[{'values':[1,2]}])

    def test_late_batch_rejection_after_trial_mutation_keeps_committed_graph(self):
        context=scope();join=EventEntityJoin(maximum_age_ticks=100);join.observe_many([pair(context,10)])
        query=event(context,20)['event'];before=join.join(query)
        first=pair(context,20,hero='would_replace');second=pair(context,20,key=2)
        second[1][0]['valid_until_ticks']=-1
        with self.assertRaisesRegex(ValueError,'proof_time'):join.observe_many([first,second])
        first[0]['provenance'].clear();first[1][0]['scope']['target']['pid']=999
        self.assertEqual(join.join(event(scope(),20)['event']),before)


if __name__=='__main__':unittest.main()
