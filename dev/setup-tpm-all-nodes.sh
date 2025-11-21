
# go into every node and enable perf events
# run with: ./setup-tpm-all-nodes [-d domain] pc820 pc803 pc813 pc808

# Default domain
DOMAIN="emulab.net"

# Parse optional domain argument
while getopts "d:" opt; do
  case ${opt} in
    d )
      DOMAIN=$OPTARG
      ;;
    \? )
      echo "Usage: $0 [-d domain] node1 node2 ..."
      exit 1
      ;;
  esac
done
shift $((OPTIND -1))

# Check if any nodes were provided
if [ $# -eq 0 ]; then
  echo "Error: No nodes specified."
  echo "Usage: $0 [-d domain] node1 node2 ..."
  exit 1
fi

NODES=("$@")  # All command-line arguments

COMMAND="git clone https://github.com/etclab/trinc.git && cd trinc && git checkout swtpm && cd swtpm-test && ./setup-tpm.sh setup_libs create_tpm test_tpm"

for NODE in "${NODES[@]}"; do
  echo "Running commands on $NODE..."
  ssh \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    apoudel@${NODE}.${DOMAIN} "${COMMAND}"
done