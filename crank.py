import re
import mmap


def find(file_path, from_bytes: bytes, to_bytes: bytes):
    with open(file_path, mode='rb') as fp:
        with mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            start_pos = mm.find(from_bytes, 0)
            end_pos = mm.find(to_bytes, start_pos + len(from_bytes))

            data = mm[start_pos:end_pos].decode('utf8')
            return data


def search(file_path, search_pattern):
    with open(file_path, mode='rb') as fp:
        with mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            found = re.search(search_pattern, mm, flags=re.DOTALL)
            if found is not None:
                return found.group(1)







