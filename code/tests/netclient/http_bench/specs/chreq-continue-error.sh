. helpers.sh

start_test_server -line 7 -file data/status-404 \
                  -reconnect \
                  -file data/simple -end
trap "stop_test_server" EXIT
request -chreq -handshake -put-small / -get / -run
