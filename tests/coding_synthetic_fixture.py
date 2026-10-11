"""Public SYNTHETIC fixtures for offline signatures and simulations.

These deterministic test keys are openly included project fixtures. They are
not owner or vendor keys and must never be supplied by a real key provider.
Prime generation and external processes are absent from this test fixture.
"""

from functools import lru_cache

from i3enet.coding_signature import RSA1024PrivateKey


# Generated independently from a deterministic test-only PRNG; public data.
_SYNTHETIC_COMPONENTS = (
    {
        "n": 0xb787d39bb762a4fea2e8534d13378b74f33ee07c0759b24788ce0d3d34a07f5f76e259da5dc70c0c1e57b35744ee92275ab530593e910eb9a036711250e5b3c07f8148bae886a68b59ef0473162dfc341e2a833723a4e3735efd1030e6cacd156ed6b891577d8c6ad70a29bc501952ec8f9e736b7f305b6e12195a0389d9e7c1,
        "e": 0x10001,
        "d": 0x292078dce62566cfe0f5aae514af57c2e75769baa1730a2e598bc30fba215529b15c5bc2414d7f779fbd0b653cff31253c8069cb35e80fa2ad3245f852c48698f4b1d592efa6c8c1e3eec290fb098b9a85bbdd004f462cf9d53546d30964e9a3d4010cd84d380f446dc64d70772b2a094da14d96f7f34d5e23b400feaaae1c79,
        "p": 0xf2f9535a761888b227ce49896674b041941968010584fe8dad06d041d82b9d612f298b1b4f01b92045500820f73ed63ffc8b15b686c409f64b0ee52892ea750f,
        "q": 0xc15ead05b6357de27516ae4c01e3161e184d3b7ddc78061638b0476399cbdce42829d5569ecea6d50ff4284096768c5ab8c08b7a3be9d66039e991804a8ef62f,
        "dp": 0xaaf043f7219c93171bb022c63ac19f7b1391683d47bfd042a65763cedf2198205648d8e8068684d2b250e2d7267b1bca7a86f368ad996014d9ab8a07288d307b,
        "dq": 0x37749a7457e4115d1fad48813dcd4d6b8616a828195146959ade5b2ae25187e0daefdc62021b4bd730c319c424228d6ffb2a25160216b6c753f47b28eab9033b,
        "qi": 0xf049ecea369a618146bee08e2538fbe2b0c56b6efad6f29c335be29340e9d1022cb369f1dd88cdfffe2e584d3c3e3667d8159dedf75e677a0f9decff638ffeee,
    },
    {
        "n": 0xb787d39bb762a4fea2e8534d13378b74f33ee07c0759b24788ce0d3d34a07f5f76e259da5dc70c0c1e57b35744ee92275ab530593e910eb9a036711250e5b3c07f8148bae886a68b59ef0473162dfc341e2a833723a4e3735efd1030e6cacd156ed6b891577d8c6ad70a29bc501952ec8f9e736b7f305b6e12195a0389d9e7c1,
        "e": 0x11,
        "d": 0x50f828a694ab8506ed849d389789723b200526cd4e89744cbc5ae7b91ebf4740b472eb67de140cd82b810b5b34ffd7115cb95918504f0e0699816e1eab3829a6ff46eb3716cdaffbe9fce772bda244ecc8c75b2ba47ec42e5b26661f683f1d0173c9013b08f9939d40c8485cbf2c17332b9d0265350c637b54d9cdb70fd036ef,
        "p": 0xf2f9535a761888b227ce49896674b041941968010584fe8dad06d041d82b9d612f298b1b4f01b92045500820f73ed63ffc8b15b686c409f64b0ee52892ea750f,
        "q": 0xc15ead05b6357de27516ae4c01e3161e184d3b7ddc78061638b0476399cbdce42829d5569ecea6d50ff4284096768c5ab8c08b7a3be9d66039e991804a8ef62f,
        "dp": 0xd66385c84a15a5ca5f5baa4c0f1baa943761b61f04dec27d0215121bfaf94ea10b7f024545b639ef4c378eb3acfb3583c0b6f50a76e935f76f677ee790b0c1a3,
        "dq": 0x5aff607b2891a4a6cdb05205a688fb5974d90cefef478a64cf62037a2a41d15c4f22bebf59caa8dcbc36a987ce55e7b238d31475c1d773f10c31ade204f7fb61,
        "qi": 0xf049ecea369a618146bee08e2538fbe2b0c56b6efad6f29c335be29340e9d1022cb369f1dd88cdfffe2e584d3c3e3667d8159dedf75e677a0f9decff638ffeee,
    },
)


def synthetic_private_components(alternate: bool = False) -> dict[str, int]:
    """Return a fresh copy of the public test-only CRT fixture."""
    if type(alternate) is not bool:
        raise ValueError("synthetic_fixture_selection_invalid")
    return dict(_SYNTHETIC_COMPONENTS[int(alternate)])


@lru_cache(maxsize=2, typed=True)
def synthetic_private_key(alternate: bool = False) -> RSA1024PrivateKey:
    """Cache validated handles for the two public synthetic keys."""
    if type(alternate) is not bool:
        raise ValueError("synthetic_fixture_selection_invalid")
    return RSA1024PrivateKey.from_components(**synthetic_private_components(alternate))
