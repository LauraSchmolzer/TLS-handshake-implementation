from fsm.states import (
    TLSContext, GenerateHelloState, ClosedState
)

if __name__ == "__main__":
    ctx = TLSContext(role="client", host="127.0.0.1", port=4444)
    state = GenerateHelloState()  # first state for client

    while not isinstance(state, ClosedState):
        state = state.run(ctx)
