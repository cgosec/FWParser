import os
import argparse
import tarfile
import gzip
import csv
import json
import logging
import re
import requests
import ipaddress
import lzma
import requests
import zipfile
import io
from datetime import datetime, timedelta

to_replace_with_delimiter = None
ip_pattern = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
public_ip_pattern = r'^([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(?<!172\.(16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31))(?<!127)(?<!^10)(?<!^0)\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(?<!192\.168)(?<!172\.(16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31))\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
replace_functions = []
batch_size = 10000
filter_for_ips = []
filter_for_ports = []
threatfox_filtering = False
threatfox_dict = {}
threatfox_days = 30
ip_validation = True
public_filter = False
threat_fox_api_url = 'https://threatfox-api.abuse.ch/api/v1/'
threatfox_full_url = 'https://threatfox.abuse.ch/export/json/ip-port/full/'

class DefaultReader():
    """
        just needed to call reader.open
    """
    open = open


def ip_range(ip_range_str):
    start_ip, end_ip = ip_range_str.split('-')
    start_ip = ipaddress.IPv4Address(start_ip)
    end_ip = ipaddress.IPv4Address(end_ip)
    return [str(ipaddress.IPv4Address(ip)) for ip in range(int(start_ip), int(end_ip) + 1)]

def read_zip_from_memory(zip_data):
    zip_file = zipfile.ZipFile(zip_data)
    file_list = zip_file.namelist()

    for file_name in file_list:
        with zip_file.open(file_name) as file:
            file_content = file.read()
            yield file_content.decode()
    return False


def get_threatfox_data(days):
    headers = {'Content-Type': 'application/json'}
    json_data = { "query": "get_iocs", "days": days }
    response = requests.post(threat_fox_api_url, headers=headers, data=json.dumps(json_data))
    return response.json()["data"]



def get_threatfox_full_list(days=30):
    today = datetime.today()
    delta = timedelta(days=days)
    oldest_time = today-delta
    response = requests.get(threatfox_full_url)
    return_dict = {}
    for list in read_zip_from_memory(io.BytesIO(response.content)):
        for id, ioc in json.loads(list).items():
            ioc = ioc[0]
            date = datetime.strptime(ioc["first_seen_utc"], "%Y-%m-%d %H:%M:%S")
            if days == 0 or date >= oldest_time:
                ip = ioc["ioc_value"].split(":")[0]
                return_dict[ip] = {
                    "confidence" : ioc["confidence_level"],
                    "malware" : ioc["malware_printable"],
                    "first_seen_utc" : ioc["first_seen_utc"]
                }
    return return_dict



def is_valid_ip_address(ip_address):
    """
    Return True if the given string is a valid IP address, False otherwise.
    """
    if not ip_validation:
        return True
    return bool(re.match(ip_pattern, ip_address))


def is_valid_port(port):
    if not ip_validation:
        return True
    try:
        port = int(port)
    except:
        return False
    return 0 <= port <= 65535


def get_all_files(paths):
    """
    Get a list of all files within a given directory path.
    """
    files = []

    for file in os.listdir(paths):
        file_path = os.path.join(paths, file)

        # Check if path is directory or file and recurse if needed
        if os.path.isdir(file_path):
            files.extend(get_all_files(file_path))
        else:
            files.append(file_path)

    return files


def read_files(file_list):
    reader = None
    extensions = set([f.split(".")[-1] for f in file_list])

    if len(extensions) > 1:
        pass  # toDo -> what if there are multiple file types?

    for file in file_list:
        file_extention = file.split(".")[-1]
        logger.debug(f"Fileextention for {file} is {file_extention}")
        if file_extention == "gz":
            reader = gzip
        elif file_extention == "xz":
            reader = lzma
        else:
            reader = DefaultReader()
        with reader.open(file, 'rt') as f:
            lines = []
            filename = os.path.splitext(os.path.basename(file))[0]
            logger.debug(f"Processing file: {filename}")
            for i, line in enumerate(f):
                lines.append(line)
                # yield every 1000 lines
                if (i + 1) % batch_size == 0:
                    yield filename, lines
                    lines = []
            # yield remaining lines
            if lines:
                yield filename, lines


def display_and_prompt(string, lst):
    """
    Print a table with the index:value of a list, then prompt for a string input and return it.
    """
    # Print table with index:value pairs
    print("Index\tValue")
    for i, val in enumerate(lst):
        print(f"{i}\t{val}")

    # Prompt for string input
    input_str = input(string)
    return input_str


def get_delimiter(file_list):
    idx = 0
    iter = read_files(file_list)
    _, str_lines = next(iter)
    current_string = str_lines[idx]
    while True:
        print(current_string)
        user_input = input("Specify delimiter")
        if user_input.lower() == "n":
            try:
                idx = idx + 1
                current_string = str_lines[idx]
            except StopIteration:
                print("End of files.")
        elif user_input.lower() == "exit":
            raise SystemExit(0)
        else:
            return user_input


def create_replace_function(str_to_replace, str_to_replace_with):
    def ret(str_line: str):
        return str_line.replace(str_to_replace, str_to_replace_with)

    replace_functions.append(ret)
    return ret


def apply_replace_functions(str_line: str):  # -> str:
    for f in replace_functions:
        str_line = f(str_line)
    return str_line


def get_positions(file_list: list, delimiter_str: str):  # -> dict:
    """
    Prompt the user for the positions of various fields until integers are provided,
    and return a dictionary mapping field names to their positions.
    """
    global replace_functions
    replace_dict = {}
    confirmed = False
    positions = {}
    field_names = ["pos_source_ip", "pos_dest_ip", "pos_source_port", "pos_dest_port", "pos_date", "pos_time"]
    lst_idx = 0
    iter = read_files(file_list=file_list)
    _, str_lines = next(iter)
    str_line = str_lines[lst_idx]
    str_line = apply_replace_functions(str_line)
    port_delimiter = None
    replacers_created = False
    print(str_line)
    while not confirmed:
        while not replacers_created:
            input_replace = input("Enter String to replace or leave blank if not needed: ")
            if not input_replace:
                confirmed = True
                break
            input_to_replace_with = input("Enter String that will replace the string to replace: ")
            rep_function = create_replace_function(str_to_replace=input_replace,
                                                   str_to_replace_with=input_to_replace_with)
            test_line = rep_function(str_line)
            replace_dict[input_replace] = input_to_replace_with
            print(test_line)
            while True:
                command = input(
                    "type 'undo' to retry if this is not correct or 'add' if you want to add more replace functions, press enter to continue. ")
                if command.lower() == "undo":
                    replace_functions = replace_functions[:-1]
                    break
                elif command.lower() == "add":
                    str_line = test_line
                    break
                elif command == "":
                    replacers_created = True
                    break
        next_example = True
        while next_example:
            lst_idx += 1
            str_line = str_lines[lst_idx]
            print("here is an other example of the output line and the columns:")
            str_line = apply_replace_functions(str_line)
            print(str_line)
            lst = str_line.split(delimiter_str)
            for i, l in enumerate(lst):
                print(f"{i}\t{l}")
            finalizes = False
            while not finalizes:
                final = input(
                    "please enter 'retry' if you want to redo or 'next' for an other example or press enter to confirm and continue: ")
                if final.lower() == "retry":
                    print("correct")
                    replace_functions = []
                    get_positions(file_list=file_list, delimiter_str=delimiter_str)
                    return
                elif final == "":
                    replacers_created = False
                    confirmed = True
                    next_example = False
                    break
                elif final == "next":
                    break

        while len(positions) < len(field_names):
            if port_delimiter and field_names[len(positions)] == "pos_dest_port":
                positions[field_names[len(positions)]] = ""
                continue
            prompt_text = f"Enter position for {field_names[len(positions)]} "
            if field_names[len(positions)] == "pos_source_port":
                prompt_text = f"Enter position for {field_names[len(positions)]} or the delimiter after the IP (e.g. :) "

            if field_names[len(positions)] == "pos_time":
                prompt_text = f"Enter position for {field_names[len(positions)]} or leave blank if included in pos_date "
            user_input = display_and_prompt(prompt_text, lst)
            try:
                position = int(user_input)
                positions[field_names[len(positions)]] = position
            except ValueError:
                if (user_input == "N"):
                    lst_idx = lst_idx + 1
                    str_line = str_lines[lst_idx]
                    str_line = apply_replace_functions(str_line)
                    lst = str_line.split(delimiter)
                if field_names[len(positions)] == "pos_source_port":
                    port_delimiter = user_input
                    positions[field_names[len(positions)]] = ""
                    print("port delimiter set")
                elif field_names[len(positions)] == "pos_time":
                    break
                else:
                    print("Invalid input. Please enter an integer value.")

        positions["delimiter"] = delimiter
        if port_delimiter:
            positions["port_delimiter"] = port_delimiter
        else:
            positions["port_delimiter"] = ""

        while True:
            wants_validation = input("Do you want to validate? (could lead to errors with e.g. IP filters) y/n")
            if wants_validation.lower() == "y":
                wants_validation = True
                break
            elif wants_validation.lower() == "n":
                wants_validation = False
                break

        while wants_validation:
            parsed_line = parse_log_line(line=str_line, **positions)
            if parsed_line == "skip":
                continue
            if not parsed_line:
                print(str_line)
                print("something went worng parsing the example line, please try again")
                lst_idx += 1
                str_line = str_lines[lst_idx]
                while True:
                    ip = input("do type 'exit' to restart the process or 'next' to skip the line")
                    if ip.lower() == "next":
                        break
                    if ip.lower() == "exit":
                        get_positions(files, delimiter)
                        return
            else:
                for key, val in parsed_line.items():
                    print(f"{key}\t{val}")
                break

        while True:
            user_input = input("Do you want to save the config? y/n ")
            if user_input.lower() == "y":
                config = {
                    "config": {
                        "replaces": replace_dict,
                    },
                    "parse_arguments": {
                        "delimiter": delimiter,
                        "port_delimiter": positions["port_delimiter"],
                        "pos_source_ip": positions["pos_source_ip"],
                        "pos_dest_ip": positions["pos_dest_ip"],
                        "pos_source_port": positions["pos_source_port"],
                        "pos_dest_port": positions["pos_dest_port"],
                        "pos_date": positions["pos_date"],
                        "pos_time": positions.get("pos_time"),
                    }
                }
                while True:
                    config_name = input("Enter a name for the config: ")
                    if os.path.exists(user_input):
                        overwrite = input(f"the file {config_name} already exists, do you want to overwrite? y/n ")
                        if overwrite.lower() == "y":
                            break
                        elif overwrite.lower() == "n":
                            continue
                    else:
                        break
                save_config(config=config, config_name=config_name)
                break
            elif user_input.lower() == "n":
                break

        return positions


def parse_log_line(line, delimiter, pos_source_ip, pos_dest_ip, pos_source_port, pos_dest_port, pos_date, pos_time=None,
                   port_delimiter=None):
    """
    Parse a log line, splitting it by delimiter and port delimiter, and returning a dictionary with the parsed values.
    """
    parsed = None
    try:
        fields = line.split(delimiter)
        source_ip = ""
        source_port = ""
        dest_ip = ""
        dest_port = ""
        if port_delimiter:
            ipPort = fields[pos_source_ip].split(port_delimiter)
            source_ip = ipPort[0]
            try:
                source_port = ipPort[1]
            except:
                source_port = "-"
            ipPort = fields[pos_dest_ip].split(port_delimiter)
            dest_ip = ipPort[0]
            try:
                dest_port = ipPort[1]
            except:
                dest_port = ""
        else:
            source_ip = fields[pos_source_ip].strip()
            source_port = fields[pos_source_port].strip()
            dest_ip = fields[pos_dest_ip].strip()
            dest_port = fields[pos_dest_port].strip()

        if not is_valid_ip_address(source_ip):
            logger.error(f"Source IP: {source_ip} is not a valid IP")
            raise ValueError
        if not is_valid_ip_address(dest_ip):
            logger.error(f"Destination IP: {dest_ip} is not a valid IP")
            raise ValueError

        if public_filter and not (re.match(public_ip_pattern, source_ip) or re.match(public_ip_pattern, dest_ip)):
            return "skip"

        if not is_valid_port(source_port) and ip_pattern != public_ip_pattern:
            logger.error(f"Source Port: {source_port} is not a valid Port")
            raise ValueError
        if not is_valid_port(dest_port) and ip_pattern != public_ip_pattern:
            logger.error(f"Destination Port: {dest_port} is not a valid Port")
            raise ValueError
        date = fields[pos_date]
        if pos_time:
            time = fields[pos_time].strip()
            date = f"{date}T{time}"

        parsed = {
            "date": date,
            "source_ip": source_ip.strip(),
            "source_port": source_port.strip(),
            "dest_ip": dest_ip.strip(),
            "dest_port": dest_port.strip(),
        }
        try:
            source_port = int(source_port)
            dest_port = int(dest_port)
        except:
            pass
        # filters
        if filter_for_ips and not (source_ip in filter_for_ips or dest_ip in filter_for_ips):
            logger.debug(f"{source_ip} or {dest_ip} did not match filters")
            logger.debug(filter_for_ips)
            return "skip"

        if filter_for_ports and not (source_port in filter_for_ports or dest_port in filter_for_ports):
            logger.debug(f"{source_port} or {dest_port} did not match filters")
            logger.debug(filter_for_ports)
            return "skip"
        
        if threatfox_filtering:
            threatfox_entry = threatfox_dict.get(parsed["dest_ip"], threatfox_dict.get(parsed["source_ip"]))
            if threatfox_entry:
                parsed["first_seen_utc"] = threatfox_entry["first_seen_utc"]
                parsed["malware"] = threatfox_entry["malware"]
                parsed["confidence"] = threatfox_entry["confidence"]
        if not parsed:
            raise ValueError("Line could not be processed")
        return parsed
    except Exception as e:
        # error longging will only happen when no filter is applied
        if parsed:
            logger.debug(parsed)
        logger.debug(e)
        if public_ip_pattern == ip_pattern or filter_for_ips or filter_for_ports:
            return "skip"
        return None


def write_to_file(objects_list, path, is_csv=True):
    """
    Write objects_list to a file at specified path.
    If is_csv is True, write objects_list to a csv file or append to an existing one.
    If is_csv is False, write objects_list to a json file or append to an existing one.
    """
    file_mode = "a" if is_csv else "a+"
    keys = objects_list[0].keys()
    file_ending = ".csv" if is_csv else ".json"
    path = path + "_fwparser"
    if threatfox_filtering:
        path = path + "_threatfox" + file_ending
    else:
        path = path + file_ending
    with open(path, file_mode, newline='') as file:
        writer = csv.DictWriter(file, keys) if is_csv else None

        if file.tell() == 0 and is_csv:
            writer.writeheader()

        for obj in objects_list:
            if is_csv:
                writer.writerow(obj)
            else:
                json.dump(obj, file)
                file.write('\n')


def create_connection_map(map: dict, source: str, destination: str, port: int, time: float) -> None:
    source_map = map.setdefault(source, {})
    destination_map = source_map.setdefault(destination, {})
    port_dict = destination_map.setdefault(port, [])
    port_dict.append(time)


def save_config(config: dict, config_name: str):
    with open(config_name + ".json", "w") as outfile:
        json.dump(config, outfile, indent=4)


def bulk_write_data_to_opensearch(url, index, data):
    bulk_data = ""
    for item in data:
        bulk_data += json.dumps({"index": {"_index": index}}) + "\n"
        bulk_data += json.dumps(item) + "\n"

    headers = {
        'Content-Type': 'application/x-ndjson'
    }

    response = requests.post(f"{url}/_bulk", headers=headers, data=bulk_data)
    if response.status_code == 200:
        logger.info(f"Successfully wrote {len(data)} items to {index}")
    else:
        logger.error(f"Error writing data. Status code: {response.status_code}")


if __name__ == "__main__":
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.ERROR)

    parser = argparse.ArgumentParser(
        prog='Firewall Parser',
        description='This tool is designed to Parse Source IP, Destination IP, Ports and Time Stamps from tar.gz firewall logs',
        epilog='--help for list of arguments')

    parser.add_argument('-d', '--dir',
                        help="Use this to parse a whole directory. Make sure only valid gz files are in there. (either -d or -f is needed)")
    parser.add_argument("-f", "--file",
                        help="Use this to parse from a single file (either this or -d is needed)")  # option that takes a value
    parser.add_argument('-t', '--delimiter',
                        help="Use this to specify the delimiter. If empty you will be asked. Or it can be specified in a config file")
    parser.add_argument('-o', '--output', help="the path were the output files will be stored, cwd if not specified")
    parser.add_argument('-n', '--name',
                        help="use this if you want to parse everything into a single file. (without file extention)")
    parser.add_argument('-ip', '--filter-ip',
                        help="'threatfox' for IPs listed in threatfox https://threatfox.abuse.ch/export/ (default 30days. set -days for custom value);\n 'public' for only entries having a public IP in source or destination; \n single ip: eg. '192.168.0.1';\n list of IPs: eg. '192.168.0.1,192.168.0.5';\nrange of ports: eg. '192.168.0.1-192.168.0.5' you can specify multiple ranges seperated by a ','")
    parser.add_argument('-days', '--threatfox-days',
                        help="'define range back in time for threatfox https://threatfox.abuse.ch/export/ IPs set to 0 will take the whole list. if not specified the default is 30 days")
    parser.add_argument('-p', '--filter-port',
                        help="single port: eg. '53', or a list of ports: eg. '53,443' or a range of ports: eg. '1-1024' you can specify multiple ranges seperated by a ','")
    parser.add_argument('-c', '--config', help="path to a config file as a .json")
    parser.add_argument('-b', '--batch-size',
                        help="By default 10000 lines will be processed. You should not go below 1000. The higher, the more RAM is used, but likely quicker")
    parser.add_argument('-x', '--format', default="csv", choices=["csv", "json"],
                        help="specify csv or json as output format")
    parser.add_argument('-z', '--disable-validation', action='store_true',
                        help="Disable the IP Validation. This is only recommented for processing e.g. DNS or Proxy Logs where the destination or source is no IP")
    parser.add_argument('-m', '--connection-map', action='store_true',
                        help="outputs a connection map as a json file having for each source a dict of each destination having a dict of each destination port having a list of timestamps")
    parser.add_argument('-v', '--verbose',
                        action='store_true', help="see more output on the console")
    parser.add_argument('-u', '--debug',
                        action='store_true', help="set logging level to debug and verbose")
    parser.add_argument('-s', '--skip-files',
                        help="number of files to skip in the list negative values will start from the end of the list and let this number of files away")

    args = parser.parse_args()

    delimiter = None
    files = None
    outputfile = None
    output_dir = None
    out_file_name = None
    field_to_position = None
    format = args.format
    csv_format = format == "csv"
    skip_files = 0
    conmap = False
    parse_arguments = None

    if args.verbose or args.debug:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO if not args.debug else logging.DEBUG)
        logger.addHandler(console_handler)
        logger.info("verbose mode")
        if args.debug:
            logger.info("debug mode")

    if args.connection_map:
        conmap = True

    if args.skip_files:
        try:
            skip_files = int(args.skip_files)
        except:
            print("skip-files parameter was not an int and will not be set")
            skip_files = 0

    if args.disable_validation:
        logger.info("IP validation disables")
        ip_validation = False

    if args.filter_port:
        ports = args.filter_port
        logger.debug(f"filtered_ports: {ports}")
        if "," in ports:
            p_split = ports.split(",")
            for p in p_split:
                if "-" in p:
                    p_start, p_end = p.split("-")
                    p_start = int(p_start)
                    p_end = int(p_end)
                    for p_sub in range(p_start, p_end + 1):
                        if not is_valid_port(p_sub):
                            logger.error(f"Invalid port in filter: {p_sub}")
                            raise ValueError
                        filter_for_ports.append(p_sub)
                else:
                    p = int(p)
                    if not is_valid_port(p):
                        logger.error(f"Invalid port in filter: {p}")
                        raise ValueError
                    filter_for_ports.append(p)
        elif "-" in ports:
            p_start, p_end = ports.split("-")
            p_start = int(p_start)
            p_end = int(p_end)
            if not is_valid_port(p_start):
                logger.error(f"Invalid port in filter: {p_start}")
                raise ValueError
            if not is_valid_port(p_end):
                logger.error(f"Invalid port in filter: {p_end}")
                raise ValueError
            for prt in range(p_start, p_end + 1):
                filter_for_ports.append(prt)
        else:
            ports = int(ports)
            if not is_valid_port(ports):
                logger.error(f"Invalid port in filter: {ports}")
                raise ValueError
            filter_for_ports.append(ports)
        filter_for_ports = [int(port) for port in filter_for_ports]
        logger.debug(f"port filters: {filter_for_ports}")

    if args.filter_ip:
        ips = args.filter_ip
        logger.debug(f"filtered_ips: {ips}")
        if ips.lower().find("public") != -1:
            public_filter = True
            ips = ips.lower().replace("public,", "")
            ips = ips.lower().replace(",public", "")
            logger.info(f"set to only public IPs")
            logger.debug(f"filtered_ips: {ips}")
        if ips.lower().find("threatfox") != -1:
            threatfox_filtering = True
            if args.threatfox_days:
                try:
                    threatfox_days =int(args.threatfox_days)
                except:
                    logger.error(f"{args.threatfox_days} is not an integer")
                    threatfox_days = 30
            threatfox_dict = get_threatfox_full_list(threatfox_days)
            filter_for_ips = threatfox_dict.keys()
            logger.debug(f"Threatfox IP-List: {filter_for_ips}")
        if "," in ips:
            ip_split = ips.split(",")
            for ip in ip_split:
                if "-" in ip:
                    filter_for_ips += ip_range(ip)
                else:
                    if not is_valid_ip_address(ip):
                        logger.error(f"Invalid IP-Address in filter: {ip}")
                        raise ValueError
                    filter_for_ips.append(ip)
        elif "-" in ips:
            filter_for_ips += ip_range(ips)
        elif ips.lower().find("public") == -1 and ips.lower().find("threatfox") == -1:
            if not is_valid_ip_address(ips):
                logger.error(f"Invalid IP-Address in filter: {ips}")
                raise ValueError
            filter_for_ips.append(ips)

    if args.dir:
        files = get_all_files(args.dir)
    elif args.file:
        files = [args.file]
    else:
        print("either -d or -f needs to be specified run with --help for more information")
        exit(0)
    if args.config:
        logger.info(f"Replace File: {args.config}")
        with open(args.config, "rt") as f:
            config_file = json.load(f)
            config = config_file["config"]
            for to_replace, to_replace_with in config["replaces"].items():
                replace_functions.append(
                    create_replace_function(str_to_replace=to_replace, str_to_replace_with=to_replace_with))
            parse_arguments = config_file["parse_arguments"]
    else:
        if (args.delimiter):
            delimiter = args.delimiter
        else:
            delimiter = get_delimiter(files)
        parse_arguments = get_positions(files, delimiter)
    if args.output:
        output_dir = args.output
    else:
        output_dir = os.getcwd()
    if args.name:
        out_file_name = args.name

    if skip_files > 0:
        files = files[skip_files:]
    if skip_files < 0:
        files = files[:skip_files]
    log_file_name = f'fwParser_{datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")}.log'
    log_file_path = os.path.join(output_dir, log_file_name)
    fh = logging.FileHandler(log_file_path)
    fh.setLevel(logging.INFO)
    logger.addHandler(fh)

    logger.info("Running with Argumtens:")
    print("Running with Argumtens:")

    if not parse_arguments:
        parse_arguments = {}

    for k, v in parse_arguments.items():
        logger.info(f"{k}\t\t{v}")
        print(f"{k}\t\t{v}")

    logger.info("Running with IP-Filters:")
    print("Running with IP-Filters:")

    if public_filter:
        logger.info(f"only entries with public IPs in source or destination")
        print(f"only entires with public IPs in source or destination")
    if threatfox_filtering:
        logger.info(f"filtering for threatfox listed IPs from the last {threatfox_days} days (0 indicates all listed IPs)")
        print(f"filtering for threatfox listed IPs from the last {threatfox_days} days (0 indicates all listed IPs)")
    logger.info(f"{', '.join(filter_for_ips)}")
    print(f"{', '.join(filter_for_ips)}")

    logger.info("Running with Port-Filters:")
    print("Running with Port-Filters:")

    logger.info(f"{', '.join([str(p) for p in filter_for_ports])}")
    print(f"{', '.join([str(p) for p in filter_for_ports])}")

    logger.info("Files to process:")
    print("Files to process:")

    for f in files:
        logger.info(f"{f}")
        print(f"{f}")

    files_count = 0
    files_sum = len(files)

    line_iterator = read_files(files)
    lines_count = 0
    current_file = 0
    done_yet = False

    if not conmap:
        while not done_yet:
            for filename, lines in line_iterator:
                if current_file != filename:
                    current_file = filename
                    files_count = files_count + 1
                    logger.info(f"processing {files_count}/{files_sum} {filename}")
                    print(f"processing {files_count}/{files_sum} {filename}")
                    files = files[:-1]
                lines_count = lines_count + batch_size
                parsed_lines = []
                for line in lines:
                    line = apply_replace_functions(line)
                    parsed = parse_log_line(line, **parse_arguments)
                    if parsed == "skip":
                        continue
                    if parsed:
                        parsed_lines.append(parsed)
                    else:
                        logger.error(f"Error parsing: {line}")
                if len(parsed_lines) > 0:
                    f_name = out_file_name if out_file_name else filename
                    full_path = os.path.join(output_dir, f_name)
                    full_path = os.path.normpath(full_path)
                    write_to_file(parsed_lines, full_path, is_csv=csv_format)
                    logger.info("wrote into " + full_path + "." + format)
                elif lines_count == batch_size:
                    retry = input(
                        f"No Line was parsed from the file {filename} do you want to retry with other positions for this file? (y/n) ")
                    if retry.lower() == "y":
                        break
                elif len(files) < 1:
                    done_yet = True
                    break
                else:
                    logger.info("nothing processed in this batch")
                    continue
            if not len(files):
                print("Done!")
                exit()

    if conmap:
        connection_map = {}
        while not done_yet:
            for filename, lines in line_iterator:
                if current_file != filename:
                    current_file = filename
                    files_count = files_count + 1
                    logger.info(f"processing {files_count}/{files_sum} {filename}")
                    print(f"processing {files_count}/{files_sum} {filename}")
                    files = files[:-1]
                lines_count = lines_count + batch_size
                for line in lines:
                    line = apply_replace_functions(line)
                    parsed = parse_log_line(line, **parse_arguments)
                    if parsed == "skip":
                        continue
                    if parsed:
                        create_connection_map(connection_map, parsed["source_ip"], parsed["dest_ip"],
                                              parsed["dest_port"], parsed["date"])
                    else:
                        logger.error(f"Error parsing: {line}")
            if not len(files):
                f_name = out_file_name if out_file_name else "connection_map"
                full_path = os.path.join(output_dir, f_name)
                full_path = os.path.normpath(full_path)
                with open(full_path + ".json", "w") as outfile:
                    json.dump(connection_map, outfile, indent=4)
                exit()
