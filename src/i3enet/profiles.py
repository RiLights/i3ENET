"""Verified module and parameter catalogue; no acquisition or signing."""
from dataclasses import dataclass

from .coding_preparation import CodingEdit, CodingPreparationError
from .coding_contract import contract

MODULES = ('HU', 'BDC', 'VSG01')
CODING_MODULES = MODULES
BDC_SOFTWARE = ('000017BE', '085.010.012', '00002418', '085.010.060')
VSG_SOFTWARE = ('00001A79', '001.003.001', '00001A77', '001.001.002')


@dataclass(frozen=True, slots=True)
class Parameter:
    group: int
    group_name: str
    offset: int
    mask: bytes
    meanings: tuple[tuple[bytes, str], ...]
    shift: int = 0
    coding_supported: bool = True
    module: str = 'HU'

    def edit(self, value: bytes, expected: bytes | None = None) -> CodingEdit:
        if not self.coding_supported:
            raise CodingPreparationError('unsupported_ecu_profile')
        allowed = dict(self.meanings)
        if value not in allowed or (expected is not None and expected not in allowed):
            raise CodingPreparationError('parameter_value_not_supported')
        encoded = bytes((value[0] << self.shift,)) if self.shift else value
        original = (None if expected is None else bytes((expected[0] << self.shift,)) if self.shift else expected)
        return CodingEdit(self.group, self.offset, encoded, self.mask, original, self.module,
                          self.mask != b'\xff' * len(self.mask))

    def decode(self, group: bytes) -> dict:
        if type(group) is not bytes or len(group) < self.offset + len(self.mask):
            raise CodingPreparationError('parameter_group_incomplete')
        value = bytes(b & m for b, m in zip(group[self.offset:], self.mask))
        if self.shift:
            value = bytes((value[0] >> self.shift,))
        meaning = dict(self.meanings).get(value)
        return dict(parameter_value_hex='0x' + value.hex().upper(),
                    parameter_meaning=meaning or 'unknown',
                    meaning_evidence_status='SOURCE_SUPPORTED' if meaning else 'UNVERIFIED')


_HU_PARAMETERS = {'EXBOX/LEGAL_DISCLAIMER_TIME': Parameter(
    0x3001, 'EXBOX', 58, b'\xff',
    ((b'\x00', 'disabled startup notice'), (b'\x0a', 'startup notice with timeout'),
     (b'\xff', 'permanent startup notice')))}

_BDC_PARAMETERS = {'PfFesMaster/FesHasMode4': Parameter(
    0x3221, 'PfFesMaster', 11, b'\x08', ((b'\x00', 'inactive'), (b'\x01', 'active')),
    shift=3, module='BDC')}

_VSG_PARAMETERS = {'VSG Configuration/Last user mode': Parameter(
    0x3000, 'VSG Configuration', 7, b'\x0f',
    ((b'\x00', 'do not remember acoustic pedestrian protection setting'),
     (b'\x01', 'remember acoustic pedestrian protection setting')),
    module='VSG01')}


def resolve_parameter(ecu: str, path: str, *, reading: bool = False) -> Parameter:
    if ecu not in MODULES:
        raise CodingPreparationError('unsupported_ecu_profile')
    parameter = {'HU':_HU_PARAMETERS,'BDC':_BDC_PARAMETERS,'VSG01':_VSG_PARAMETERS}[ecu].get(path)
    if parameter is None:
        raise CodingPreparationError('unknown_parameter_path')
    return parameter


def module_identity(ecu: str) -> dict:
    if ecu not in MODULES: return dict(diagnostic_address=None, cafd=None, btld=None)
    if ecu == 'VSG01':
        return dict(diagnostic_address='0x2D', cafd='/'.join(VSG_SOFTWARE[:2]), btld='/'.join(VSG_SOFTWARE[2:]))
    spec = contract(ecu)
    return dict(diagnostic_address=f'0x{spec.target:02X}', cafd=spec.cafd, btld=spec.btld)
