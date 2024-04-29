function run_command {
    local user=$1
    local command=$2
    local log_file=$3
    local current_dir=$(pwd)  # Get the current directory

    echo "Running command as $user: $command"
    
    # Run command as specified user and log output
    sudo -u $user bash -c "$command" > /dev/null 2>&1 
}

# Execute commands concurrently
run_command "user1" "./bin/reportman_client 127.0.0.1 test123.txt manufacturing" "log_user1.txt" &
run_command "user2" "./bin/reportman_client 127.0.0.1 test123.txt distribution" "log_user2.txt" &
run_command "user3" "./bin/reportman_client 127.0.0.1 test123.txt marketing" "log_user3.txt" &

# Wait for all jobs to complete
wait