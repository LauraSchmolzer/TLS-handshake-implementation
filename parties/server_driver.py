from fsm.states import (
    TLSContext, OpenListeningState, ClosedState
)

if __name__ == "__main__":
    ctx = TLSContext(role="server", host="127.0.0.1", port=4444)
    state = OpenListeningState()  # first state for server

    while not isinstance(state, ClosedState):
        state = state.run(ctx)
