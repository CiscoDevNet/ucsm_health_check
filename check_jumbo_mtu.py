import re
from crank import search


# Helper function
def split_into_indented_blocks(show_running_config_output: str):
    """ Splits a `show running-config` output into blocks containing one config section"""
    for block in re.split(r'\n(?=\S)', show_running_config_output, flags=re.MULTILINE):
        yield block


def check_jumbo_mtu(sw_techsupportinfo='./logFiles/sw_techsupportinfo'):
    command = search(sw_techsupportinfo, br'`show running-config \| grep -v username`(.*?)\n`')

    def generate_results():
        for block in split_into_indented_blocks(command.decode('utf8')):
            if block.startswith('policy-map type network-qos'):
                sub_blocks = re.split(r'\n(?=\s+class)', block, flags=re.MULTILINE)
                class_definitions = sub_blocks[1:]
                for entry in class_definitions:
                    name = re.search(r'\s+class type network-qos (.*)', entry).group(1)
                    nodrop = 'pause no-drop' in entry
                    mtu = int(re.search(r'\s+mtu (.*)', entry).group(1))

                    yield name, nodrop, mtu

    results = [(name, nodrop, mtu) for name, nodrop, mtu in generate_results() if mtu <= 1500]
    if len(results):
        return {
            "Status": "FOUND",
            "Result": f"Found policies where jumbo frames are not enabled: "
                      f"{','.join(repr(name) for name, nodrop, mtu in results)}"

        }

    return {
        "Status": "NOT_FOUND",
        "Result": "All policies have jumbo frames enabled"
    }



