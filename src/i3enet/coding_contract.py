"""Exact supported module coding geometry; no IO or permission."""
from dataclasses import dataclass

@dataclass(frozen=True, slots=True)
class CodingContract:
    module: str
    target: int
    cafd: str
    btld: str
    groups: tuple[tuple[int, int], ...]
    receive_chunks: int

    @property
    def requests(self):
        return tuple(bytes.fromhex('000000050001f4') + bytes((self.target, 0x22)) + a.to_bytes(2,'big') for a, _ in self.groups)

    @property
    def signing_bytes(self):
        return sum(n for _, n in self.groups[:-1])

HU = CodingContract('HU', 0x63, '00000DED/003.015.041', '00001ABA/130.026.001',
    ((0x3000,152),(0x3001,151),(0x3002,150),(0x3003,150),(0x3004,150),(0x3005,150),(0x3006,8),(0x3007,132)), 64)
BDC = CodingContract('BDC', 0x40, '000017BE/085.010.012', '00002418/085.010.060',
    (
        (0x3000,22), (0x3001,86), (0x3002,80), (0x3003,144), (0x3004,56),
        (0x3020,152), (0x3021,4), (0x3022,13), (0x3023,2), (0x3030,32),
        (0x3031,14), (0x3032,252), (0x3033,110), (0x3034,252), (0x3035,48),
        (0x3036,252), (0x3037,48), (0x3038,252), (0x3039,48), (0x3040,22),
        (0x3041,58), (0x3050,19), (0x3051,20), (0x3052,128), (0x3053,128),
        (0x3054,128), (0x3055,128), (0x3056,15), (0x3057,3), (0x3058,2),
        (0x3059,2), (0x3060,216), (0x3061,128), (0x3062,195), (0x3063,195),
        (0x3064,247), (0x3065,237), (0x3066,252), (0x3067,252), (0x3068,34),
        (0x3069,248), (0x3070,165), (0x3071,179), (0x3072,189), (0x3073,252),
        (0x3074,157), (0x3075,3), (0x3076,252), (0x3080,30), (0x3085,8),
        (0x3090,28), (0x30A0,44), (0x30B0,5), (0x30C0,16), (0x30D0,27),
        (0x30E0,4), (0x3100,1), (0x3101,3), (0x3105,10), (0x3110,16),
        (0x3111,21), (0x3115,3), (0x3120,34), (0x3130,12), (0x3131,78),
        (0x3140,19), (0x3150,3), (0x3160,2), (0x3180,128), (0x3181,128),
        (0x3182,128), (0x3184,128), (0x3190,7), (0x3200,15), (0x3210,40),
        (0x3221,17), (0x3223,1), (0x3420,14), (0x3421,1), (0x3422,21),
        (0x37FC,8), (0x37FD,132),
    ), 328)
VSG = CodingContract('VSG01', 0x2D, '00001A79/001.003.001', '00001A77/001.001.002',
    ((0x3000,8),(0x3001,8),(0x3002,132)), 64)

def contract(module):
    if type(module) is not str or module not in ('HU','BDC','VSG01'):
        raise ValueError('unsupported_module_contract')
    return {'HU':HU,'BDC':BDC,'VSG01':VSG}[module]

def software_contract(cafd, btld):
    for selected in (HU, BDC, VSG):
        if type(cafd) is str and type(btld) is str and (cafd,btld)==(selected.cafd,selected.btld):
            return selected
    raise ValueError('unsupported_software_tuple')

def transaction_stages(module):
    spec = contract(module)
    coding = ('current_vin', 'current_svk', *(f'original_{a:04x}' for a, _ in spec.groups),
              *(('current_cps',) if module != 'HU' else ()),
              'extended_session', 'coding_session', 'security_seed', 'security_key',
              *(f'write_{a:04x}' for a, _ in spec.groups), 'check_signature', 'write_cps', 'read_cps',
              'reset' if module == 'HU' else 'default_session')
    post = ('post_vin', 'post_svk', 'post_ping', *(f'readback_{a:04x}' for a, _ in spec.groups), 'post_cps')
    return coding, post

def transaction_bounds(module):
    spec = contract(module); coding, post = transaction_stages(module)
    return (len(coding) + len(post), 33 * len(spec.groups) + sum(n for _, n in spec.groups)
            + sum((22, 22, 11, 22, 18, 12, 10, 20, 14, 142)) + (11 if module != 'HU' else 0), max(128, 4 * len(coding)))

def initial_read_frames(module):
    spec = contract(module)
    return (bytes.fromhex('000000050001f41022f190'),
            bytes.fromhex('000000050001f4') + bytes((spec.target, 0x22, 0xF1, 0x01)),
            *spec.requests, *((bytes.fromhex('000000050001f4') + bytes((spec.target,0x22,0x37,0xFE)),) if module != 'HU' else ()))
