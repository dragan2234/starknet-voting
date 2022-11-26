%lang starknet

%builtins pedersen range_check ecdsa

from starkware.cairo.common.cairo_builtins import HashBuiltin

@storage_var
func poll_result(poll_id : felt) -> (result : felt){
}

@external
func record{syscall_ptr : felt*, range_check_ptr, pedersen_ptr : HashBuiltin*}(
        poll_id : felt, result : felt){
    poll_result.write(poll_id=poll_id, value=result);
    return ();
}

@view
func get_poll_result{syscall_ptr : felt*, range_check_ptr, pedersen_ptr : HashBuiltin*}(
        poll_id : felt) -> (result : felt){
    let (result) = poll_result.read(poll_id=poll_id);
    return (result=result);
}