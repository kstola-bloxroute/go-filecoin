package consensus

import (
	"context"
	"fmt"
	"math/big"

	"go.opencensus.io/tag"
	"go.opencensus.io/trace"

	"github.com/filecoin-project/go-filecoin/internal/pkg/block"
	"github.com/filecoin-project/go-filecoin/internal/pkg/metrics"
	"github.com/filecoin-project/go-filecoin/internal/pkg/metrics/tracing"
	"github.com/filecoin-project/go-filecoin/internal/pkg/types"
	"github.com/filecoin-project/go-filecoin/internal/pkg/vm"
	"github.com/filecoin-project/go-filecoin/internal/pkg/vm/actor"
	"github.com/filecoin-project/go-filecoin/internal/pkg/vm/actor/builtin"
	"github.com/filecoin-project/go-filecoin/internal/pkg/vm/actor/builtin/initactor"
	"github.com/filecoin-project/go-filecoin/internal/pkg/vm/actor/builtin/miner"
	"github.com/filecoin-project/go-filecoin/internal/pkg/vm/address"
	"github.com/filecoin-project/go-filecoin/internal/pkg/vm/errors"
	"github.com/filecoin-project/go-filecoin/internal/pkg/vm/state"
)

var (
	// Tags
	msgMethodKey = tag.MustNewKey("consensus/keys/message_method")

	// Timers
	amTimer = metrics.NewTimerMs("consensus/apply_message", "Duration of message application in milliseconds", msgMethodKey)
)

// MessageValidator validates the syntax and semantics of a message before it is applied.
type MessageValidator interface {
	// Validate checks a message for validity.
	Validate(ctx context.Context, msg *types.UnsignedMessage, fromActor *actor.Actor) error
}

// ApplicationResult contains the result of successfully applying one message.
// ExecutionError might be set and the message can still be applied successfully.
// See ApplyMessage() for details.
type ApplicationResult struct {
	Receipt        *types.MessageReceipt
	ExecutionError error
}

// ApplyMessageResult is the result of applying a single message.
type ApplyMessageResult struct {
	ApplicationResult        // Application-level result, if error is nil.
	Failure            error // Failure to apply the message
	FailureIsPermanent bool  // Whether failure is permanent, has no chance of succeeding later.
}

// DefaultProcessor handles all block processing.
type DefaultProcessor struct {
	validator MessageValidator
	actors    builtin.Actors
}

var _ Processor = (*DefaultProcessor)(nil)

// NewDefaultProcessor creates a default processor from the given state tree and vms.
func NewDefaultProcessor() *DefaultProcessor {
	return &DefaultProcessor{
		validator: NewDefaultMessageValidator(),
		actors:    builtin.DefaultActors,
	}
}

// NewConfiguredProcessor creates a default processor with custom validation and rewards.
func NewConfiguredProcessor(validator MessageValidator, actors builtin.Actors) *DefaultProcessor {
	return &DefaultProcessor{
		validator: validator,
		actors:    actors,
	}
}

// ProcessTipSet computes the state transition specified by the messages in all
// blocks in a TipSet.  It is similar to ProcessBlock with a few key differences.
// Most importantly ProcessTipSet relies on the precondition that each input block
// is valid with respect to the base state st, that is, ProcessBlock is free of
// errors when applied to each block individually over the given state.
// ProcessTipSet only returns errors in the case of faults.  Other errors
// coming from calls to ApplyMessage can be traced to different blocks in the
// TipSet containing conflicting messages and are returned in the result slice.
// Blocks are applied in the sorted order of their tickets.
func (p *DefaultProcessor) ProcessTipSet(ctx context.Context, st state.Tree, vms vm.Storage, ts block.TipSet, msgs []vm.BlockMessagesInfo) (results []vm.MessageReceipt, err error) {
	ctx, span := trace.StartSpan(ctx, "DefaultProcessor.ProcessTipSet")
	span.AddAttributes(trace.StringAttribute("tipset", ts.String()))
	defer tracing.AddErrorEndSpan(ctx, span, &err)

	h, err := ts.Height()
	if err != nil {
		return nil, errors.FaultErrorWrap(err, "processing empty tipset")
	}
	epoch := types.NewBlockHeight(h)

	vm := vm.NewVM(st, vms)

	return vm.ApplyTipSetMessages(msgs, *epoch)
}

var (
	// These errors are only to be used by ApplyMessage; they shouldn't be
	// used in any other context as they are an implementation detail.
	errFromAccountNotFound       = errors.NewRevertError("from (sender) account not found")
	errGasAboveBlockLimit        = errors.NewRevertError("message gas limit above block gas limit")
	errGasPriceZero              = errors.NewRevertError("message gas price is zero")
	errGasTooHighForCurrentBlock = errors.NewRevertError("message gas limit too high for current block")
	errNonceTooHigh              = errors.NewRevertError("nonce too high")
	errNonceTooLow               = errors.NewRevertError("nonce too low")
	errNonAccountActor           = errors.NewRevertError("message from non-account actor")
	errNegativeValue             = errors.NewRevertError("negative value")
	errInsufficientGas           = errors.NewRevertError("balance insufficient to cover transfer+gas")
	errInvalidSignature          = errors.NewRevertError("invalid signature by sender over message data")
	// TODO we'll eventually handle sending to self.
	errSelfSend = errors.NewRevertError("cannot send to self")
)

// CallQueryMethod calls a method on an actor in the given state tree. It does
// not make any changes to the state/blockchain and is useful for interrogating
// actor state. Block height bh is optional; some methods will ignore it.
func (p *DefaultProcessor) CallQueryMethod(ctx context.Context, st state.Tree, vms vm.StorageMap, to address.Address, method types.MethodID, params []byte, from address.Address, optBh *types.BlockHeight) ([][]byte, uint8, error) {
	// not committing or flushing storage structures guarantees changes won't make it to stored state tree or datastore
	cachedSt := state.NewCachedTree(st)

	msg := &types.UnsignedMessage{
		From:       from,
		To:         to,
		CallSeqNum: 0,
		Value:      types.ZeroAttoFIL,
		Method:     method,
		Params:     params,
	}

	// Set the gas limit to the max because this message send should always succeed; it doesn't cost gas.
	gasTracker := vm.NewLegacyGasTracker()
	gasTracker.MsgGasLimit = types.BlockGasLimit

	// translate address before retrieving from actor
	toAddr, found, err := ResolveAddress(ctx, msg.To, cachedSt, vms, gasTracker)
	if err != nil {
		return nil, 1, errors.FaultErrorWrapf(err, "Could not resolve actor address")
	}

	if !found {
		return nil, 1, errors.ApplyErrorPermanentWrapf(err, "failed to resolve To actor")
	}

	toActor, err := st.GetActor(ctx, toAddr)
	if err != nil {
		return nil, 1, errors.ApplyErrorPermanentWrapf(err, "failed to get To actor")
	}

	vmCtxParams := vm.NewContextParams{
		To:          toActor,
		ToAddr:      toAddr,
		Message:     msg,
		OriginMsg:   msg,
		State:       cachedSt,
		StorageMap:  vms,
		GasTracker:  gasTracker,
		BlockHeight: optBh,
		Actors:      p.actors,
	}

	vmCtx := vm.NewVMContext(vmCtxParams)
	ret, retCode, err := vm.Send(ctx, vmCtx)
	return ret, retCode, err
}

// PreviewQueryMethod estimates the amount of gas that will be used by a method
// call. It accepts all the same arguments as CallQueryMethod.
func (p *DefaultProcessor) PreviewQueryMethod(ctx context.Context, st state.Tree, vms vm.StorageMap, to address.Address, method types.MethodID, params []byte, from address.Address, optBh *types.BlockHeight) (types.GasUnits, error) {
	// not committing or flushing storage structures guarantees changes won't make it to stored state tree or datastore
	cachedSt := state.NewCachedTree(st)

	msg := &types.UnsignedMessage{
		From:       from,
		To:         to,
		CallSeqNum: 0,
		Value:      types.ZeroAttoFIL,
		Method:     method,
		Params:     params,
	}

	// Set the gas limit to the max because this message send should always succeed; it doesn't cost gas.
	gasTracker := vm.NewLegacyGasTracker()
	gasTracker.MsgGasLimit = types.BlockGasLimit

	// ensure actor exists
	toActor, toAddr, err := getOrCreateActor(ctx, cachedSt, vms, msg.To, gasTracker)
	if err != nil {
		return types.GasUnits(0), errors.FaultErrorWrap(err, "failed to get To actor")
	}

	vmCtxParams := vm.NewContextParams{
		To:          toActor,
		ToAddr:      toAddr,
		Message:     msg,
		OriginMsg:   msg,
		State:       cachedSt,
		StorageMap:  vms,
		GasTracker:  gasTracker,
		BlockHeight: optBh,
		Actors:      p.actors,
	}
	vmCtx := vm.NewVMContext(vmCtxParams)
	_, _, err = vm.Send(ctx, vmCtx)

	return vmCtx.GasUnits(), err
}

// attemptApplyMessage encapsulates the work of trying to apply the message in order
// to make ApplyMessage more readable. The distinction is that attemptApplyMessage
// should deal with trying to apply the message to the state tree whereas
// ApplyMessage should deal with any side effects and how it should be presented
// to the caller. attemptApplyMessage should only be called from ApplyMessage.
func (p *DefaultProcessor) attemptApplyMessage(ctx context.Context, st *state.CachedTree, store vm.StorageMap, msg *types.UnsignedMessage, bh *types.BlockHeight, gasTracker *vm.LegacyGasTracker, ancestors []block.TipSet) (*types.MessageReceipt, error) {
	gasTracker.ResetForNewMessage(msg)
	if err := blockGasLimitError(gasTracker); err != nil {
		return &types.MessageReceipt{
			ExitCode:   errors.CodeError(err),
			GasAttoFIL: types.ZeroAttoFIL,
		}, err
	}

	fromAddr, found, err := ResolveAddress(ctx, msg.From, st, store, gasTracker)
	if err != nil {
		return nil, errors.FaultErrorWrapf(err, "Could not resolve actor address")
	}
	if !found {
		return &types.MessageReceipt{
			ExitCode:   errors.CodeError(err),
			GasAttoFIL: types.ZeroAttoFIL,
		}, errFromAccountNotFound
	}

	fromActor, err := st.GetActor(ctx, fromAddr)
	if state.IsActorNotFoundError(err) {
		return &types.MessageReceipt{
			ExitCode:   errors.CodeError(err),
			GasAttoFIL: types.ZeroAttoFIL,
		}, errFromAccountNotFound
	} else if err != nil {
		return nil, errors.FaultErrorWrapf(err, "failed to get From actor %s", msg.From)
	}

	err = p.validator.Validate(ctx, msg, fromActor)
	if err != nil {
		return &types.MessageReceipt{
			ExitCode:   errors.CodeError(err),
			GasAttoFIL: types.ZeroAttoFIL,
		}, err
	}

	// ensure actor exists
	toActor, toAddr, err := getOrCreateActor(ctx, st, store, msg.To, gasTracker)
	if err != nil {
		return nil, errors.FaultErrorWrap(err, "failed to get To actor")
	}

	vmCtxParams := vm.NewContextParams{
		From:        fromActor,
		To:          toActor,
		ToAddr:      toAddr,
		Message:     msg,
		OriginMsg:   msg,
		State:       st,
		StorageMap:  store,
		GasTracker:  gasTracker,
		BlockHeight: bh,
		Ancestors:   ancestors,
		Actors:      p.actors,
	}
	vmCtx := vm.NewVMContext(vmCtxParams)

	ret, exitCode, vmErr := vm.Send(ctx, vmCtx)
	if errors.IsFault(vmErr) {
		return nil, vmErr
	}

	// compute gas charge
	gasCharge := msg.GasPrice.MulBigInt(big.NewInt(int64(vmCtx.GasUnits())))

	receipt := &types.MessageReceipt{
		ExitCode:   exitCode,
		GasAttoFIL: gasCharge,
	}

	receipt.Return = append(receipt.Return, ret...)

	return receipt, vmErr
}

// ResolveAddress looks up associated id address. If the given address is already and id address, it is returned unchanged.
func ResolveAddress(ctx context.Context, addr address.Address, st *state.CachedTree, vms vm.StorageMap, gt *vm.LegacyGasTracker) (address.Address, bool, error) {
	if addr.Protocol() == address.ID {
		return addr, true, nil
	}

	init, err := st.GetActor(ctx, address.InitAddress)
	if err != nil {
		return address.Undef, false, err
	}

	vmCtx := vm.NewVMContext(vm.NewContextParams{
		State:      st,
		StorageMap: vms,
		ToAddr:     address.InitAddress,
		To:         init,
	})

	id, found, err := initactor.LookupIDAddress(vmCtx, addr)
	if err != nil {
		return address.Undef, false, err
	}

	if !found {
		return address.Undef, false, nil
	}

	idAddr, err := address.NewIDAddress(id)
	if err != nil {
		return address.Undef, false, err
	}

	return idAddr, true, nil
}

// ApplyMessagesAndPayRewards pays the block mining reward to the miner's owner and then applies
// messages, in order, to a state tree.
// Returns a message application result for each message.
func (p *DefaultProcessor) ApplyMessagesAndPayRewards(ctx context.Context, st state.Tree, vms vm.StorageMap,
	messages []*types.UnsignedMessage, minerOwnerAddr address.Address, bh *types.BlockHeight,
	ancestors []block.TipSet) ([]*ApplyMessageResult, error) {
	var results []*ApplyMessageResult

	// // Pay block reward.
	// if err := p.blockRewarder.BlockReward(ctx, st, vms, minerOwnerAddr); err != nil {
	// 	return nil, err
	// }

	// // Process all messages.
	// gasTracker := vm.NewLegacyGasTracker()
	// for _, msg := range messages {
	// 	r, err := p.ApplyMessage(ctx, st, vms, msg, minerOwnerAddr, bh, gasTracker, ancestors)
	// 	switch {
	// 	case errors.IsFault(err):
	// 		return nil, err
	// 	case errors.IsApplyErrorPermanent(err):
	// 		results = append(results, &ApplyMessageResult{ApplicationResult{}, err, true})
	// 	case errors.IsApplyErrorTemporary(err):
	// 		results = append(results, &ApplyMessageResult{ApplicationResult{}, err, false})
	// 	case err != nil:
	// 		panic("someone is a bad programmer: error is neither fault, perm or temp")
	// 	default:
	// 		results = append(results, &ApplyMessageResult{*r, nil, false})
	// 	}
	// }

	// Dragons: do something
	return results, fmt.Errorf("re-write or delete")
}

// ApplyMessageDirect applies a given message directly to the given state tree and storage map and returns the result of the message.
// This is a shortcut to allow internal code to use built-in actor functionality to alter state.
func ApplyMessageDirect(ctx context.Context, st state.Tree, vms vm.StorageMap, from, to address.Address, nonce uint64, value types.AttoFIL, method types.MethodID, params ...interface{}) ([]byte, error) {
	// Dragons: this is here jus tto make the genesis code and gengen compile
	return []byte{}, nil
}

func blockGasLimitError(gasTracker *vm.LegacyGasTracker) error {
	if gasTracker.GasAboveBlockLimit() {
		return errGasAboveBlockLimit
	} else if gasTracker.GasTooHighForCurrentBlock() {
		return errGasTooHighForCurrentBlock
	}
	return nil
}

func isTemporaryError(err error) bool {
	return err == errFromAccountNotFound ||
		err == errNonceTooHigh ||
		err == errGasTooHighForCurrentBlock
}

func isPermanentError(err error) bool {
	return err == errInsufficientGas ||
		err == errSelfSend ||
		err == errInvalidSignature ||
		err == errNonceTooLow ||
		err == errNonAccountActor ||
		err == errNegativeValue ||
		err == errors.Errors[errors.ErrCannotTransferNegativeValue] ||
		err == errGasAboveBlockLimit
}

// minerOwnerAddress finds the address of the owner of the given miner
func (p *DefaultProcessor) minerOwnerAddress(ctx context.Context, st state.Tree, vms vm.StorageMap, minerAddr address.Address) (address.Address, error) {
	ret, code, err := p.CallQueryMethod(ctx, st, vms, minerAddr, miner.GetOwner, []byte{}, address.Undef, types.NewBlockHeight(0))
	if err != nil {
		return address.Undef, errors.FaultErrorWrap(err, "could not get miner owner")
	}
	if code != 0 {
		return address.Undef, errors.NewFaultErrorf("could not get miner owner. error code %d", code)
	}
	return address.NewFromBytes(ret[0])
}

func getOrCreateActor(ctx context.Context, st *state.CachedTree, store vm.StorageMap, addr address.Address, gt *vm.LegacyGasTracker) (*actor.Actor, address.Address, error) {
	// resolve address before lookup
	idAddr, found, err := ResolveAddress(ctx, addr, st, store, gt)
	if err != nil {
		return nil, address.Undef, err
	}

	if found {
		act, err := st.GetActor(ctx, idAddr)
		return act, idAddr, err
	}

	initAct, err := st.GetActor(ctx, address.InitAddress)
	if err != nil {
		return nil, address.Undef, err
	}

	// this should never fail due to lack of gas since gas doesn't have meaning here
	noopGT := vm.NewLegacyGasTracker()
	noopGT.MsgGasLimit = 10000 // must exceed gas units consumed by init.Exec+account.Constructor+init.GetActorIDForAddress
	vmctx := vm.NewVMContext(vm.NewContextParams{Actors: builtin.DefaultActors, To: initAct, State: st, StorageMap: store, GasTracker: noopGT})
	vmctx.Send(address.InitAddress, initactor.ExecMethodID, types.ZeroAttoFIL, []interface{}{types.AccountActorCodeCid, []interface{}{addr}})

	vmctx = vm.NewVMContext(vm.NewContextParams{Actors: builtin.DefaultActors, To: initAct, State: st, StorageMap: store, GasTracker: noopGT})
	idAddrInt := vmctx.Send(address.InitAddress, initactor.GetActorIDForAddressMethodID, types.ZeroAttoFIL, []interface{}{addr})

	id, ok := idAddrInt.(*big.Int)
	if !ok {
		return nil, address.Undef, errors.NewFaultError("non-integer return from GetActorIDForAddress")
	}

	idAddr, err = address.NewIDAddress(id.Uint64())
	if err != nil {
		return nil, address.Undef, err
	}

	act, err := st.GetActor(ctx, idAddr)
	return act, idAddr, err
}

// directMessageValidator is a validator that doesn't validate to simplify message creation in tests.
type directMessageValidator struct{}

// Validate always returns nil
func (tsmv *directMessageValidator) Validate(ctx context.Context, msg *types.UnsignedMessage, fromActor *actor.Actor) error {
	return nil
}
