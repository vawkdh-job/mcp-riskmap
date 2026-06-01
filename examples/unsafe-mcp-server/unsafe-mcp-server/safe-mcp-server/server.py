
def read_file_safe(filename):
    if ".." in filename or filename.startswith("/"):
        return "Доступ заборонено: спроба зламати систему!"
    return open(filename).read()
