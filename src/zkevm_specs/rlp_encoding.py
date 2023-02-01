from typing import Sequence, Tuple, Set, NamedTuple
from collections import namedtuple
from .util import keccak256, EMPTY_HASH, FQ, RLC
from .evm import get_push_size, RlpEncodingTag, RlpEncodingTableRow
from .encoding import is_circuit_code

# Row in the circuit, TODO: how to have column layout in multiple lines ? 
Row = namedtuple(
    "Row",
    "q_enable q_first q_last is_final index tag value length_rindex length_acc block_length depth parent_rindex data_rindex value_rlc hash keccak_tuple padding"
)

# Unrolled rlp encoding
class UnrolledRlpEncoding(NamedTuple):
    bytes: bytes
    rows: Sequence[RlpEncodingTableRow]

@is_circuit_code
def check_rlp_encoding_row(
    prev: Row,
    cur: Row,
    next: Row, # do we need further rows ? i.e., are there other constraints of higher order ?
    randomness: int, # to compute value_rlc field
):
    prev = Row(*[v if isinstance(v, RLC) else FQ(v) for v in prev])
    cur = Row(*[v if isinstance(v, RLC) else FQ(v) for v in cur])
    next = Row(*[v if isinstance(v, RLC) else FQ(v) for v in next])

    # we need to check the tag of the row, depending on the tag, we proceed to
    # verify constraints. See https://hackmd.io/@rohitnarurkar/S1zSz0KM9 for 
    # more details, on which constraints we have to impose
    if cur.tag == RlpEncodingTag.LengthOfLength:
        tag_length_of_length_circuit_verification(prev, cur, next)
    elif cur.tag == RlpEncodingTag.Length:
        tag_length_circuit_verification(prev, cur, next)
    elif cur.tag == RlpEncodingTag.Data:
        tag_data_circuit_verification(prev, cur, next)

    # additional constraints
    additional_constraints_circuit_verification(prev, cur, next, randomness)
        
@is_circuit_code
def tag_length_of_length_circuit_verification(prev: Row, cur: Row, next: Row):
     # value 
        assert (cur.value in range(0xb8, 0xbf)) | (cur.value in range(0xf8, 0xff))
        # length_acc
        assert cur.length_acc == 0
        # data_rindex and block_length
        assert cur.data_rindex == cur.block_length

        # parent_rindex
        if cur.q_first:     
            assert cur.parent_rindex == 0
            # we further assert that the prev row is None, (not in the explicit constraints in the link above)
            assert prev == None
        elif prev.data_rindex == 1:
            assert cur.data_rindex == prev.data_rindex - prev.block_length
        else:
            assert cur.parent_rindex == prev.data_rindex

        # depth
        if cur.q_first:
            assert cur.depth == 0 
            # don't need to recheck that prev is None
        elif prev.data_rindex == 1:
            assert cur.depth == prev.depth
        else:
            assert cur.depth == prev.depth + 1
        
        # tag
        assert next.tag == RlpEncodingTag.Length

        # length_rindex (we already checked what are the possible values for cur.value)
        lvalue = cur.value - 0xb7 if cur.value in range(0xb8, 0xbf) else cur.value - 0xf7
        assert next.length_rindex == lvalue

@is_circuit_code
def tag_length_circuit_verification(prev: Row, cur: Row, next: Row):
    if cur.value in range(0x80, 0xb7): 
        lvalue = cur.value - 0xb0
    elif cur.value in range(0xc0, 0xf7):
        lvalue = cur.value - 0xc0
    else:
        lvalue = cur.value

    # length_acc
    assert cur.length_acc == prev.length_acc * 256 + lvalue
    # data_rindex and block_length:
    # case in which current is q_first and if current depth
    # equals previous depth, or not.

    # first row starts with default values
    if cur.q_first: 
        assert cur.data_rindex == cur.block_length
        assert cur.parent_rindex == 0
        assert cur.depth == 0 
        assert next.tag == RlpEncodingTag.Data
        assert cur.length_rindex == 1

    if cur.depth == prev.depth:
        if prev.data_rindex == 1:
            assert cur.data_rindex == cur.block_length
        else: 
            assert cur.data_rindex == prev.data_rindex - 1
            assert cur.block_length == prev.block_length
    else:
        cur.data_rindex == cur.block_length
    
    # parent_rindex
    if prev.data_rindex == 1:
        assert cur.parent_rindex == prev.parent_rindex - prev.block_length
    else: 
        assert cur.parent_rindex == prev.data_rindex
    
    # depth
    if prev.data_rindex == 0:
        assert cur.depth == prev.depth
    else: 
        assert cur.depth == prev.depth + 1

    # tag
    if cur.depth == prev.depth:
        if cur.length_rindex > 1:
            assert next.tag == RlpEncodingTag.Length
            assert cur.length_rindex == next.length_rindex + 1
        elif cur.length_rindex == 1 & cur.depth == next.depth:
            assert next.tag == RlpEncodingTag.Data
            assert cur.length_acc == next.data_rindex
        elif cur.length_rindex == 1 & cur.depth == next.depth + 1:
            if next.value in range(0x80, 0xb7 + 1) | next.value in range(0xc0, 0xf7 + 1):
                assert next.tag == RlpEncodingTag.Length
            elif next.value in range(0xb8, 0xbf + 1) | next.value in range(0xf8, 0xff + 1):
                assert next.tag == RlpEncodingTag.LengthOfLength
    elif cur.depth == prev.depth + 1:
        assert next.tag == RlpEncodingTag.Data
        assert cur.length_rindex == 1 
        
@is_circuit_code
def tag_data_circuit_verification(prev: Row, cur: Row, next: Row):
    # length_rindex
    assert cur.length_rindex == 0
    
    # length_acc
    assert cur.length_acc == 0

    # block_length
    if cur.depth == prev.depth:
        assert cur.block_length == prev.block_length

        if cur.depth == prev.depth - 1:
            # TODO: missing information in the link above
            print("To be implemented")
        
    # data_rindex
    if cur.data_rindex > 1:
        # TODO: missing information in the link above
        print("To be implemented")
    elif cur.data_rindex == 1:
        # TODO: missing information in the link above
        print("To be implemented")

@is_circuit_code
def additional_constraints_circuit_verification(prev: Row, cur: Row, next: Row, randomness: int):
    assert cur.is_final in range(0, 2) # i.e., cur.is_final is a boolean value, is there a nicer way to express this ? 
    assert cur.padding in range(0, 2)

    # for q_first row
    if cur.q_first:
        assert cur.value == cur.value_rlc
        assert cur.index == 0
    else: 
        assert cur.index == prev.index + 1
        assert cur.hash == prev.hash # what is the reasoning behind this ? 
        assert cur.value_rlc == (prev.value_rlc * randomness) + cur.value
        # padding can only go from 0 -> 1
        assert cur.padding - prev.padding in range(0, 2)

    # for q_last row which is not part of padding
    if cur.q_last & ~cur.padding:
        assert cur.value_rlc == cur.keccak_tuple[0]
        assert cur.index + 1 == cur.keccak_tuple[1]
        assert cur.hash == cur.keccak_tuple[2]

    # for q_last row, which is not padding
    if cur.q_last:
        assert cur.is_final | cur.padding == 1

# Populate the circuit matrix
def assign_rlp_encoding_circuit(k: int, rlp_encodings: Sequence[UnrolledRlpEncoding], randomness: int):
    # all rows are usable, with padding if necessary
    # k should correspond to a well defined notion of 'size' of the circuit
    last_row_offset = 2 ** k - 1

    rows = []
    offset = 0
    for rlp_encoding in rlp_encodings:
        value_rlc = FQ(0) # element in the field
        for idx, row in enumerate(rlp_encoding.rows):
            # subsequent rows are deemed to represent rlp_encoding bytes
            # we need to track which bytes correspond to either of the tags
            # Tag::LengthOfLength, Tag::Length, Tag::Data
            is_final = rlp_encoding.rows[idx + 1].value.expr().n >= 128 # range of data value itself
                                                                        # TODO: is .n the right way to get a number of a FQ ? 
            value = row.value.expr().n # TODO: is this the right way to recover the underlying integer byte number ? 
            index = 0 if value >= 128 else index + 1
            # it is pretty straighforward to define the tag, from the row.value itself
            # TODO: we can make this more idiomatic by using new Python's match functionality
            tag = compute_tag_from_value(value)
            # it is also possible to define the correct value of lenght_rindex
            # we basically iterate over the next rows with tag == Length
            # and add 1 to length_rindex, notice that length_rindex is supposed
            # to be decreasing
            length_rindex = 0
            if tag == RlpEncodingTag.Length:
                aux_idx = idx + 1
                next_tag = tag
                while next_tag == RlpEncodingTag.Length & aux_idx < len(rlp_encoding.rows):
                    length_rindex += 1
                    next_tag = compute_tag_from_value(rlp_encoding.rows[aux_idx].value.expr().n)
                    aux_idx += 1
            # computing length_acc, in this case the accumulator is cumulative, so 
            length_acc = 0
            if tag == RlpEncodingTag.Length:
                exp = 0
                prev_tag = tag
                while prev_tag == RlpEncodingTag.Length & idx - exp > -1:
                    length_acc += rlp_encoding.rows[idx - exp].value * (256 ** exp)
            # computing the block length, the block length is constant across
            # values of same tag and same depth. 
            if tag == RlpEncodingTag.LengthOfLength:
                length_of_length = row.tag
            value_rlc = value_rlc * randomness + row.value

            # set the data for this row
            rows.append(
                Row(
                    q_enable = 1, # TODO: tracks if current row is enable in the layout, 
                                  # if I undestand it correctly, every row should be enabled
                    q_first = offset == 0,
                    q_last = offset == last_row_offset,
                    is_final = is_final,
                    index = index,
                    tag = tag,
                    value = value,
                    length_rindex = length_rindex,
                )
            )

def compute_tag_from_value(value: int):
    if value < 128:
        tag = RlpEncodingTag.Data
    elif value in range(128, 184) | value in range(192, 247):
        tag = RlpEncodingTag.Length
    elif value in range(184, 192) | value in range(247, 256):
        tag = RlpEncodingTag.LengthOfLength
    else:
        raise Exception("Invalid byte value for RLP encoding")
    
    return tag