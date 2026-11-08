import sys
import struct
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from inference import scan, unpack, InferenceError
from crypto_core import expand, extract
from bootstrap import interpret

class InferenceTests(unittest.TestCase):
    def test_address_propagation_tracks_relocated_material(self):
        def image(address):
            # movz x0,address; mov w1,32; mov x2,x0; mov w3,64; bl; ret
            words=[0xd2800000 | address<<5,0x52800401,0xaa0003e2,0xd2800803,0x94000004,0xd65f03c0]
            return struct.pack('<6I',*words)
        for address in (0x1000,0x2000):
            calls,_=scan(image(address))
            self.assertEqual(calls[0]['args'][:4],[address,32,address,64])

    def test_invalid_native_fails_without_profile_fallback(self):
        with self.assertRaises(InferenceError):unpack(b'bad')

    def test_hkdf_known_vector(self):
        prk=extract(bytes(range(13)),bytes([11])*22)
        self.assertEqual(expand(prk,bytes(range(240,250)),42).hex(),
            '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865')

    def test_interpreter_rejects_unsupported_instruction(self):
        class Instruction:
            def get_name(self):return 'monitor-enter'
            def get_operands(self):return [(0,0)]
            def get_length(self):return 2
        class Body:
            def get_ins_size(self):return 1
            def get_registers_size(self):return 1
        class Method:
            def get_code(self):return Body()
            def get_access_flags(self):return 8
            def get_instructions_idx(self):return [(0,Instruction())]
        with self.assertRaises(InferenceError):interpret(Method(),bytearray(32))

if __name__=='__main__':unittest.main()
