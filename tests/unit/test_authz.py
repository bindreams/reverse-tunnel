import ctypes

from ctl import authz


def test_the_groups_of_a_token_groups_structure_start_at_the_next_pointer_aligned_offset_after_its_count():
    # Entries hold a pointer, so they follow the 4-byte count at 4 on 32-bit Python and at 8 on 64-bit Python.
    assert authz.TOKEN_GROUPS_OFFSET == ctypes.sizeof(ctypes.c_void_p)
