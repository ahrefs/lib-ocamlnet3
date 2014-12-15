. helpers.sh

start_test_server -line 6 -file data/simple -reconnect -line 1 -file data/simple -end
trap "stop_test_server" EXIT
request -unframed-put / -get / -run
