%lang starknet

%builtins pedersen range_check ecdsa

from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin
from starkware.cairo.common.hash import hash2
from starkware.cairo.common.math import assert_not_zero
from starkware.cairo.common.math_cmp import is_le
from starkware.cairo.common.signature import verify_ecdsa_signature

@constructor
func constructor{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr} (result_recorder_address : felt) {
    result_recorder.write(value=result_recorder_address);
    return ();
}

// # Storage variables.

@storage_var
func poll_owner_public_key(poll_id : felt) -> (public_key : felt){
}

@storage_var
func voting_state(poll_id : felt, answer : felt) -> (n_votes : felt){
}

@storage_var
func registered_voters(poll_id : felt, voter_public_key : felt) -> (is_registered : felt){
}

@storage_var
func voter_state(poll_id : felt, voter_public_key : felt) -> (has_voted : felt){
}

@storage_var
func result_recorder() -> (contract_address : felt){
}

//
@external
func init_poll{syscall_ptr : felt*, range_check_ptr, pedersen_ptr : HashBuiltin*}(
        poll_id : felt, public_key : felt){
    let (is_poll_id_taken) = poll_owner_public_key.read(poll_id=poll_id);
    // # Verify that the poll ID is available.
    assert is_poll_id_taken = 0;

    poll_owner_public_key.write(poll_id=poll_id, value=public_key);
    return ();
}

@external
func register_voter{
        syscall_ptr : felt*, range_check_ptr, pedersen_ptr : HashBuiltin*,
        ecdsa_ptr : SignatureBuiltin*}(poll_id : felt, voter_public_key : felt, r : felt, s : felt){
    let (owner_public_key) = poll_owner_public_key.read(poll_id=poll_id);
    // # Verify that the poll is initialized.
    assert_not_zero(owner_public_key);

    // # Verify the validity of the signature.
    let (message) = hash2{hash_ptr=pedersen_ptr}(x=poll_id, y=voter_public_key);
    verify_ecdsa_signature(
        message=message, public_key=owner_public_key, signature_r=r, signature_s=s);

    // # Register voter.
    registered_voters.write(poll_id=poll_id, voter_public_key=voter_public_key, value=1);
    return ();
}

@external
func vote{
        syscall_ptr : felt*, range_check_ptr, pedersen_ptr : HashBuiltin*,
        ecdsa_ptr : SignatureBuiltin*}(
        poll_id : felt, voter_public_key : felt, vote : felt, r : felt, s : felt){
    // # Verify the vote.
    verify_vote(poll_id=poll_id, voter_public_key=voter_public_key, vote=vote, r=r, s=s);

    // # Vote.
    let (current_n_votes) = voting_state.read(poll_id=poll_id, answer=vote);
    voting_state.write(poll_id=poll_id, answer=vote, value=current_n_votes + 1);
    voter_state.write(poll_id=poll_id, voter_public_key=voter_public_key, value=1);
    return ();
}

@view
func get_voting_state{syscall_ptr : felt*, range_check_ptr, pedersen_ptr : HashBuiltin*}(
        poll_id : felt) -> (n_no_votes : felt, n_yes_votes : felt){
    let (n_no_votes) = voting_state.read(poll_id=poll_id, answer=0);
    let (n_yes_votes) = voting_state.read(poll_id=poll_id, answer=1);
    return (n_no_votes=n_no_votes, n_yes_votes=n_yes_votes);
}

// # Private helpers.

func verify_vote{
        pedersen_ptr : HashBuiltin*, syscall_ptr : felt*, ecdsa_ptr : SignatureBuiltin*,
        range_check_ptr}(poll_id : felt, voter_public_key : felt, vote : felt, r : felt, s : felt){
    // # Verify that the vote value is legal, i.e., 0 or 1.
    assert (vote - 0) * (vote - 1) = 0;

    let (is_registered) = registered_voters.read(poll_id=poll_id, voter_public_key=voter_public_key);
    // # Verify that the voter is registered.
    assert_not_zero(is_registered);

    // # Verify that the voter has not voted for this poll yet.
    let (has_voted) = voter_state.read(poll_id=poll_id, voter_public_key=voter_public_key);
    assert has_voted = 0;

    // # Verify the validity of the signature.
    let (message) = hash2{hash_ptr=pedersen_ptr}(x=poll_id, y=vote);
    verify_ecdsa_signature(
        message=message, public_key=voter_public_key, signature_r=r, signature_s=s);
    return ();
}

@external
func finalize_poll{syscall_ptr : felt*, range_check_ptr, pedersen_ptr : HashBuiltin*}(
        poll_id : felt){
    alloc_locals;

    let (local result_recorder_address) = result_recorder.read();
    
    local pedersen_ptr: HashBuiltin* = pedersen_ptr;
 
    
    let (n_no_votes, n_yes_votes) = get_voting_state(poll_id=poll_id);

    // # Store these references in local variables as they might be revoked by is_le().
    local syscall_ptr : felt* = syscall_ptr;
    local pedersen_ptr : HashBuiltin* = pedersen_ptr;

    let result = is_le(n_no_votes, n_yes_votes);
    // # Demonstrate Cairo short strings. "Yes" == int.from_bytes("Yes".encode("ascii"), "big").
    let result = (result * 'Yes') + ((1 - result) * 'No');

    // # Record the poll result in a ResultRecorder contract.
    let (result) = ResultRecorder.get_poll_result(result_recorder_address, poll_id);
    assert result = 0;
    ResultRecorder.record(contract_address=result_recorder_address, poll_id=poll_id, result=result);
    return ();
}

// # Interfaces.

@contract_interface
namespace ResultRecorder{
    func record(poll_id : felt, result : felt){
    }
	func get_poll_result(poll_id: felt) -> (result: felt){
    }
}