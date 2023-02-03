from typing import Sequence, Tuple, Set, NamedTuple
from collections import namedtuple
from .util import keccak256, EMPTY_HASH, FQ, RLC
from .evm import get_push_size, RlpEncodingTag, RlpEncodingTableRow
from .encoding import is_circuit_code

# Row in the circuit, TODO: how to have column layout in multiple lines ? 
# TODO: do we need a parent_rindex ? It seems we can compute the data_rindex
# from the block_length alone. Moreover, it seems possible to compute the
# block_length without any knowledge of parent_rindex.
# In https://github.com/scroll-tech/zkevm-circuits/blob/scroll-stable/zkevm-circuits/src/rlp_circuit.rs,
# both parent_rindex and depth are not used explicitly
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
        prev_block_length = 0 # previous block length starts at 0
        prev_row_block_length = 0 # previous row value of block_length, starts at 0
        prev_depth = 0 # previous depth starts at 0
        prev_data_rindex = 2 ** 64 # pick a large number for starting previous data_rindex
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

            # computing length_acc, in this case the accumulator is cumulative
            length_acc = compute_length_acc_from_encoding(tag, rlp_encoding.rows, idx)
    
            # computing the block length, the block length is constant across
            # values of same tag and same depth. 
            block_length = compute_block_length_from_encoding(tag, rlp_encoding.rows, idx)

            # compute data_rindex
            if offset == 0:
                depth = 0
                data_rindex = block_length
            elif tag == RlpEncodingTag.LengthOfLength:
                data_rindex = block_length
                if prev_data_rindex == 1:
                    depth = prev_depth
                else:
                    depth = prev_depth + 1
            elif tag == RlpEncodingTag.Length | tag == RlpEncodingTag.Data:
                # the first condition is unnecessary, for tag Length, I think.
                # Indeed, a Length tag is always followed by non-empty data after, 
                # in the same block. Therefore, we will never have a data_rindex = 1
                # for Length tag.
                if prev_data_rindex == 1:
                    data_rindex = block_length
                else:
                    data_rindex = prev_data_rindex - 1
                
                # this condition should not be applied to tag == Data,
                if prev_data_rindex == 1:
                    depth = prev_depth
                else:
                    depth = prev_depth
            
            # parent_data_rindex might not be necessary
            # at all for the circuit specification. See
            # the TODO in the beginning of this file
            parent_data_rindex = prev_block_length

            # update previous block_length, data_rindex, depth
            if prev_row_block_length != block_length:
                prev_block_length = prev_row_block_length
                
            prev_row_block_length = block_length
            prev_block_length = block_length
            prev_data_rindex = data_rindex
            prev_depth = depth

            # compute the value_rlc recursively   
            value_rlc = value_rlc * randomness + row.value
            # hash of the rlp encoded bytes
            hash = keccak256(bytes(row)) # TODO: check how to properly extract the bytes from row
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
                    length_acc = length_acc,
                    block_length = block_length,
                    depth = depth,
                    data_rindex = data_rindex,
                    hash = hash,
                    keccak_tuple = (value_rlc, len(row), hash),
                    padding = False,
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

def compute_length_acc_from_encoding(tag: RlpEncodingTag, rows: Sequence[Row], current_idx: int):
    length_acc = 0
    if tag == RlpEncodingTag.Length:
        exp = 0
        prev_tag = tag
        while prev_tag == RlpEncodingTag.Length & current_idx - exp > -1:
            length_acc += rows[current_idx - exp].value * (256 ** exp)

    return length_acc

def compute_block_length_from_encoding(tag: RlpEncodingTag, rows: Sequence[Row], current_idx: int):
    row = rows[current_idx]
    # computing the block length, the block length is constant across
    # values of same tag and same depth. 
    if tag == RlpEncodingTag.LengthOfLength:
        length_of_length = row.value
        # not strictly necessary, but we are conservative
        assert length_of_length in range(184, 192) | length_of_length in range(248, 256)
        
        # we are in the case of a start of a list of elements or a string, 
        # whose length is big. The corresponding block corresponds to the 
        # whole list/string size (after encoding)
        # this is captured by the length_acc of the last row corresponding to the last
        # byte of the encoded length.
        length_of_length -= 183 if length_of_length in range(184, 192) else 247

        # we compute the length_acc of the last row corresponding to the final length_of_length row
        # so we get the total number of values of the original array
        total_length_acc = compute_length_acc_from_encoding(
            RlpEncodingTag.Length, rows, current_idx + length_of_length
        )
        # the final block length should be equal to total_length_acc plus the bytes used
        # to specify both the length encoding (length_of_length) and the length_of_length (1)
        block_length = total_length_acc + 1 + length_of_length
    elif tag == RlpEncodingTag.Length:
        length = row.value
        increment = 0
        if length in range(128, 184):
            a = 128
            b = 184
        elif length in range(192, 248):
            a = 192
            b = 248
        else:
            raise Exception("Invalid byte value for length")
        total_length_acc = compute_length_acc_from_encoding(tag, rows, current_idx)
        # iterate until the last byte specifying the length of rlp encoded data block
        while rows[current_idx + increment].value in range(a, b):
            total_length_acc = compute_length_acc_from_encoding(
                RlpEncodingTag.Length, rows, current_idx + increment
            )
    elif tag == RlpEncodingTag.Data:
        # in this case, the block_length should be equal to the block_length of the length encoding
        decrement = 0
        while rows[current_idx + decrement].value <= 127 & decrement > -current_idx:
            decrement -= 1
        # let's make sure the closest length byte is of tag RlpEncodingTag.Length
        assert rows[current_idx + decrement].value in range(128, 184) | rows[current_idx + decrement].value in range(192, 248)
        block_length = compute_block_length_from_encoding(RlpEncodingTag.Length, rows, current_idx + decrement)
    
    return block_length
