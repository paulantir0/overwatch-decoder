import http.client
import importlib.util
import json
import tempfile
import threading
import unittest
from functools import partial
from http.server import ThreadingHTTPServer
from pathlib import Path

spec = importlib.util.spec_from_file_location('replay_serve', Path(__file__).with_name('serve.py'))
serve = importlib.util.module_from_spec(spec)
spec.loader.exec_module(serve)


def environment_fixture():
    build = 'b'*64
    survey = {'schema':'overwatch-decoder.environment-surface-samples/1', 'map':'Workshop Chamber', 'mode':'Skirmish',
        'observed_build_sha256':build, 'coordinate_space':'workshop_world', 'replay_registration':None,
        'visibility':'unknown', 'coverage':'sparse_first_hit_rays',
        'source':{'kind':'inspector_log_file', 'sha256':'c'*64, 'rule_sha256':'d'*64, 'position_tolerance':0.025},
        'rays':[{'index':0, 'origin':[0,0,0], 'end':[0,0,20], 'returned_hit':[0,0,10],
                 'returned_normal':[0,0,-1], 'status':'surface_hit'}]}
    return {'schema':'overwatch-decoder.replay-environment/1', 'replay_source_sha256':'a'*64,
        'observed_build_sha256':build, 'map':'Workshop Chamber', 'mode':'Skirmish',
        'registration':{'kind':'identity', 'validation':'controlled_coordinate_pairs', 'evidence_sha256':'e'*64},
        'surveys':[survey]}


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.replay = Path(cls.directory.name) / 'data.json'
        cls.replay.write_text('{"private_test":true}')
        cls.video = Path(cls.directory.name) / 'private-video.mp4'
        cls.video.write_bytes(bytes(range(256)))
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), partial(serve.Handler,
            replay=cls.replay, video=cls.video, video_offset=1.9, video_uncertainty=1.68, chunks={"/chunks/0000.json":cls.replay}))
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join()
        cls.server.server_close()
        cls.directory.cleanup()

    def get(self, path, headers=None, method='GET', server=None):
        connection = http.client.HTTPConnection('127.0.0.1', (server or self.server).server_port)
        connection.request(method, path, headers=headers or {})
        response = connection.getresponse()
        result = response.status, dict(response.getheaders()), response.read()
        connection.close()
        return result

    def test_only_explicit_replay_and_ui_are_served(self):
        self.assertEqual(self.get('/')[0], 200)
        self.assertEqual(self.get('/app.js')[0], 200)
        self.assertEqual(self.get('/evidence.js')[0], 200)
        self.assertEqual(self.get('/environment.js')[0], 200)
        status, headers, body = self.get('/replay.json')
        self.assertEqual((status, body), (200, b'{"private_test":true}'))
        self.assertEqual(headers['Cache-Control'], 'no-store')
        self.assertNotIn('Access-Control-Allow-Origin', headers)
        self.assertIn("frame-ancestors 'none'", headers['Content-Security-Policy'])
        for path in ['/../README.md', '/prepare.py', '/%2e%2e/README.md', '/data.json', '/.runs/', '/private-video.mp4']:
            self.assertEqual(self.get(path)[0], 404)

    def test_reject_rebinding_and_cross_site_requests(self):
        for headers in [{'Host':'attacker.example'}, {'Origin':'https://attacker.example'},
                        {'Sec-Fetch-Site':'cross-site'}]:
            self.assertEqual(self.get('/replay.json', headers)[0], 403)
        port = self.server.server_port
        self.assertEqual(self.get('/replay.json', {'Origin':f'http://127.0.0.1:{port}'})[0], 200)

    def test_top_level_ui_navigation_does_not_allow_cross_site_data(self):
        headers={'Sec-Fetch-Site':'cross-site','Sec-Fetch-Mode':'navigate','Sec-Fetch-Dest':'document'}
        self.assertEqual(self.get('/',headers)[0],200)
        self.assertEqual(self.get('/replay.json',headers)[0],403)
        self.assertEqual(self.get('/chunks/0000.json',headers)[0],403)
        self.assertEqual(self.get('/media.json',headers)[0],403)
        self.assertEqual(self.get('/',{**headers,'Sec-Fetch-Dest':'iframe'})[0],403)
        self.assertEqual(self.get('/',{**headers,'Origin':'https://attacker.example'})[0],403)

    def test_only_explicit_chunk_urls_are_served(self):
        self.assertEqual(self.get('/chunks/0000.json')[2],self.replay.read_bytes())
        for url in ('/chunks/0001.json','/chunks/../data.json','/chunks/0000.json/extra'):
            self.assertEqual(self.get(url)[0],404)

    def test_head_does_not_send_body(self):
        status, headers, body = self.get('/replay.json', method='HEAD')
        self.assertEqual(status,200)
        self.assertEqual(int(headers['Content-Length']),len(self.replay.read_bytes()))
        self.assertEqual(body,b'')

    def test_video_seeking_ranges_and_head(self):
        for value, start, end in [('bytes=0-9', 0, 9), ('bytes=240-', 240, 255),
                                  ('bytes=-3', 253, 255), ('bytes=250-999', 250, 255)]:
            status, headers, body = self.get('/gameplay.mp4', {'Range': value})
            self.assertEqual(status, 206)
            self.assertEqual(headers['Content-Range'], f'bytes {start}-{end}/256')
            self.assertEqual(body, bytes(range(256))[start:end+1])
            self.assertEqual(int(headers['Content-Length']), len(body))
        status, headers, body = self.get('/gameplay.mp4', {'Range': 'bytes=20-29'}, 'HEAD')
        self.assertEqual((status, headers['Content-Length'], body), (206, '10', b''))
        self.assertEqual(self.get('/gameplay.mp4')[2], bytes(range(256)))

    def test_invalid_video_ranges_do_not_fall_back_to_full_download(self):
        for value in ['bytes=256-', 'bytes=9-1', 'bytes=-0', 'bytes=-', 'bytes=0-2,4-6',
                      'arbitrary', 'bytes=' + '9'*120 + '-']:
            status, headers, body = self.get('/gameplay.mp4', {'Range': value})
            self.assertEqual(status, 416, value)
            self.assertEqual(headers['Content-Range'], 'bytes */256')
            self.assertEqual(body, b'')
        self.assertEqual(self.get('/gameplay.mp4', {'Origin':'https://attacker.example'})[0], 403)

    def test_media_metadata_exposes_no_private_paths(self):
        status, headers, body = self.get('/media.json')
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)['video'], {'url':'/gameplay.mp4',
            'start_seconds':1.9, 'uncertainty_seconds':1.68, 'alignment':'estimated'})
        self.assertNotIn(self.directory.name.encode(), body)
        self.assertEqual(headers['Cache-Control'], 'no-store')
        self.assertEqual(self.get('/media.json', {'Host':'attacker.example'})[0], 403)

    def test_environment_endpoint_requires_explicit_attachment_and_same_origin(self):
        self.assertEqual(self.get('/environment.json')[0],404)
        self.assertNotIn('environment',json.loads(self.get('/media.json')[2]))
        document = environment_fixture()
        payload = serve.checked_environment(document, 'a'*64)
        with ThreadingHTTPServer(('127.0.0.1',0), partial(serve.Handler, replay=self.replay, environment=payload)) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                media = self.get('/media.json', server=server)
                self.assertEqual(json.loads(media[2])['environment'],{'url':'/environment.json'})
                status,headers,body = self.get('/environment.json',server=server)
                self.assertEqual((status,json.loads(body)), (200,document))
                self.assertEqual(headers['Cache-Control'],'no-store')
                self.assertEqual(headers['Cross-Origin-Resource-Policy'],'same-origin')
                self.assertEqual(self.get('/environment.json',method='HEAD',server=server)[2],b'')
                self.assertEqual(self.get('/environment.json',{'Sec-Fetch-Site':'cross-site'},server=server)[0],403)
                self.assertEqual(self.get('/environment.json',{'Origin':'https://attacker.example'},server=server)[0],403)
                self.assertEqual(self.get('/environment.json/extra',server=server)[0],404)
            finally:
                server.shutdown()
                thread.join()


class EnvironmentTests(unittest.TestCase):
    def test_requires_replay_and_coordinate_registration(self):
        document = environment_fixture()
        self.assertEqual(json.loads(serve.checked_environment(document, 'a'*64)),document)
        for source in ('d'*64, None, ''):
            with self.subTest(source=source), self.assertRaisesRegex(ValueError,'match'):
                serve.checked_environment(document, source)
        for registration in [None, {}, {'kind':'identity','validation':'manual','evidence_sha256':'a'*64},
                             {'kind':'identity','validation':'controlled_coordinate_pairs','evidence_sha256':''}]:
            with self.subTest(registration=registration), self.assertRaisesRegex(ValueError,'registration'):
                serve.checked_environment({**document,'registration':registration}, 'a'*64)

    def test_rejects_mismatched_surveys_and_excess_counts(self):
        document = environment_fixture()
        survey = document['surveys'][0]
        for key,value in [('map','Oasis'),('mode','Control'),('observed_build_sha256','f'*64),('visibility','visible')]:
            with self.subTest(key=key), self.assertRaisesRegex(ValueError,'scope'):
                serve.checked_environment({**document,'surveys':[{**survey,key:value}]}, 'a'*64)
        large = {**survey,'rays':[{**survey['rays'][0], 'index':i} for i in range(500)]}
        for surveys in [[], [survey]*17, [{**survey,'rays':survey['rays']*501}],
                        [large]*9]:
            with self.subTest(count=len(surveys)), self.assertRaisesRegex(ValueError,'count'):
                serve.checked_environment({**document,'surveys':surveys}, 'a'*64)

    def test_patch_cannot_reference_a_miss_or_unknown_ray_index(self):
        document = environment_fixture()
        survey = document['surveys'][0]
        survey['rays'] = [{**survey['rays'][0], 'index':i} for i in range(4)]
        survey['planar_patches'] = [{'kind':'derived_between_samples','ray_indices':[0,1,2,4]}]
        with self.assertRaisesRegex(ValueError,'corners'):
            serve.checked_environment(document, 'a'*64)
        survey['planar_patches'][0]['ray_indices'][-1] = 3
        survey['rays'][3]['status'] = 'miss_or_endpoint'
        with self.assertRaisesRegex(ValueError,'corners'):
            serve.checked_environment(document, 'a'*64)


class CalibrationTests(unittest.TestCase):
    def setUp(self):
        self.document = {'schema':'overwatch-decoder.replay-alignment/1', 'source_sha256':'a'*64,
            'video_sha256':'b'*64, 'offset_seconds':3.57, 'uncertainty_seconds':0.1,
            'method':'independent motion observations', 'scope':'reviewed intervals'}

    def check(self, data):
        return serve.checked_alignment(data, 'a'*64, 'b'*64)

    def test_calibration_requires_both_source_and_video(self):
        result = self.check(self.document)
        self.assertEqual(result['alignment'], 'motion_calibrated')
        self.assertEqual(result['start_seconds'], 3.57)
        self.assertEqual(result['uncertainty_seconds'], 0.1)
        for key in ['schema', 'source_sha256', 'video_sha256']:
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.check({**self.document, key:'wrong'})

    def test_invalid_or_unbounded_timing_is_rejected(self):
        for key, values in [('offset_seconds', [None, True, '3.57', float('nan'), float('inf'), 3601]),
                            ('uncertainty_seconds', [None, False, '0.1', float('nan'), float('inf'), -0.1])]:
            for value in values:
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    self.check({**self.document, key:value})

    def test_evidence_document_is_bounded_and_an_object(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'labels.json'
            for text in ['[]', 'null', '{}'+(' '*(1024*1024))]:
                path.write_text(text)
                with self.assertRaises(ValueError):
                    serve.read_document(path)
            path.write_text('{"schema":"example"}')
            self.assertEqual(serve.read_document(path), {'schema':'example'})


if __name__ == '__main__':
    unittest.main()
