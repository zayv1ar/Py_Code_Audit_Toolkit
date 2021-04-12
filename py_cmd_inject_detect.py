# -*- coding:utf-8 -*-

import subprocess
import sys
import re
import argparse

grep_pattern = re.compile(r'(.*):(\d+):(.*)')
constant_pattern = re.compile(r'constant\..*|CONSTANT\..*|const\..*|CONST\..*')
replace_pattern = re.compile(r'(.*?) % (.*)')
tuple_replace_pattern = re.compile(r'(.*?) % \((.*?,.*)\)$')
variable_name_pattern = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]*$')
num_pattern = re.compile(r'[1-9][0-9]*')
cmd_assignment_pattern = re.compile(r'cmd=(.*)')

# "subprocess", "subprocess32", "system"
cmd_execute_funcs = ["runcmd", "runcmd_nowait"]


def findout_cmd_execute_funcs():
    pass


def deep_search(param, file_location):
    line_number = 0
    variable_content = ""
    param_pattern = re.compile(param + r' = (.*)')
    with open(file_location, 'r') as f:
        codes = f.readlines()
        for line in codes:
            line = line.strip()
            line_number += 1
            param_pattern_res = param_pattern.match(line)
            if param_pattern_res:
                temp_line_number = line_number
                if line[-1] == "," or line[-1] == "\\" or line[-1] == "(":
                    if line[-1] == "\\":
                        variable_content += param_pattern_res.group(1)[:-1]
                    else:
                        variable_content += param_pattern_res.group(1)

                    temp_line_number += 1
                    line = codes[temp_line_number - 1].strip()

                    while line[-1] == "," or line[-1] == "\\" or line[-1] == "(":
                        if line[-1] == "," or line[-1] == "(":
                            variable_content += line
                        else:
                            if line[:-1].strip()[-1] == '"' \
                                    and codes[temp_line_number].strip()[0] == '"':
                                variable_content += line[:-1].strip()[:-1]
                                codes[temp_line_number] = codes[temp_line_number].strip()[1:]
                            else:
                                variable_content += line[:-1]
                        temp_line_number += 1
                        line = codes[temp_line_number].strip()
                    variable_content += line
                else:
                    variable_content += param_pattern_res.group(1)
                return True, variable_content, line_number
    return False, "", line_number


def get_front_code_context(file_location, line_number):
    context = list()
    line_num = int(line_number)
    with open(file_location, 'r') as f:
        codes = f.readlines()
        if line_num >= search_depth:
            for i in range(0, search_depth):
                temp = [str(i + (line_num - search_depth + 1)), codes[i + (line_num - search_depth)][:-1]]
                context.append(temp)
        else:
            for i in range(1, line_num+1):
                temp = [str(i), codes[i-1][:-1]]
                context.append(temp)
    return context


def show_front_code_context(front_code_context):
    print("\n\033[37mFront code context:\033[0m")
    for line in front_code_context:
        print("\033[37m" + line[0] + "    \033[37m" + line[1] + "\033[0m")


def get_code_by_loc(file_location, line_number):
    with open(file_location, 'r') as f:
        codes = f.readlines()
        func_call = codes[int(line_number) - 1].lstrip()
        func_call_rstrip = func_call.rstrip()
        if func_call_rstrip[-1] == ")":
            return func_call
        else:
            # such as func(args)[0]
            if func_call_rstrip[-1] == "]" and func_call_rstrip[-3] == "[" and func_call_rstrip[-4] == ")":
                return func_call
            else:
                return func_call[:-1] + get_code_by_loc(file_location, int(line_number) + 1)


def cmd_inject_detect():
    total_count = 0
    risk_count = 0
    safe_list = []
    for cmd_execute_func in cmd_execute_funcs:
        print("\n\033[34m------------------------------------ scan func " + cmd_execute_func +
              "() ------------------------------------\033[0m\n")
        func_total_count = 0
        func_risk_count = 0
        func_safe_count = 0
        func_safe_list = []
        items = subprocess.getstatusoutput("grep " + '"' + cmd_execute_func +
                                           '("' + " -rn " + root_path + " | grep -v Binary | grep -v def")[1]
        for item in items.split("\n"):
            func_total_count += 1
            res = grep_pattern.match(item)
            file_location = res[1]
            line_number = res[2]
            func_call = get_code_by_loc(file_location, line_number)

            print("\n\033[34m------------------------------------ Dividing Line "
                  "------------------------------------\033[0m\n")
            print("\033[37m" + file_location + ":" + line_number + "    " + func_call[:-1] + "\033[0m")

            cmd_param_pattern = re.compile(r'.*' + cmd_execute_func + r'\(' + r'(.*)' + r'\)')
            multi_param_pattern = re.compile(r'.*' + cmd_execute_func + r'\(' + r'(.*?),.*' + r'\)')

            # try:
            multi_param_pattern_res = multi_param_pattern.match(func_call)
            if multi_param_pattern_res:
                if " % (" in func_call:
                    cmd_param_pattern_res = cmd_param_pattern.match(func_call)
                    param = cmd_param_pattern_res.group(1)
                else:
                    param = multi_param_pattern_res.group(1)
            else:
                cmd_param_pattern_res = cmd_param_pattern.match(func_call)
                param = cmd_param_pattern_res.group(1)

            cmd_assignment_pattern_res = cmd_assignment_pattern.match(param)
            if cmd_assignment_pattern_res:
                param = cmd_assignment_pattern_res.group(1)

            if judge(param, file_location, line_number):
                func_risk_count += 1
                front_code_context = get_front_code_context(file_location, line_number)
                if debug:
                    print("\n\033[33m[*] Need manual investigation\033[0m")
                show_front_code_context(front_code_context)
            else:
                if debug:
                    print("\n\033[32m[*] No cmd inject risk\033[0m")
                func_safe_count += 1
                func_safe_list.append("\033[37m" + file_location + ":" + line_number +
                                      "    " + func_call + "\033[0m\n")

            # except Exception as e:
            #     print(e.__class__.__name__ + ":", e)
            #     continue

        print("\n\033[34m------------------------------------ Report of func " + cmd_execute_func +
              "() ------------------------------------\033[0m\n")
        print("\033[34mfunc_total_count:" + str(func_total_count) + "\033[0m")
        print("\033[34mfunc_risk_count:" + str(func_risk_count) + "\033[0m")
        print("\033[34mfunc_safe_count:" + str(func_safe_count) + "\033[0m")

        total_count += func_total_count
        risk_count += func_risk_count
        safe_list.append(func_safe_list)

    print("\n\033[34m------------------------------------ Total Report " +
          "------------------------------------\033[0m\n")
    print("\033[34mtotal_count:" + str(total_count) + "\033[0m")
    print("\033[34mrisk_count:" + str(risk_count) + "\033[0m")
    print("\033[34msafe_count:" + str(total_count - risk_count) + "\033[0m")

    print("\n\033[34m------------------------------------ safe call filtered " +
          "------------------------------------\033[0m\n")

    if show_safe_calls:
        for func_safe_list in safe_list:
            for safe_call in func_safe_list:
                print(safe_call)


# 判断命令字符串是否有外部注入风险
def judge(param, file_location, line_number):
    if debug:
        print("\n\033[34m[*] Judge inject risk of: " + param + "\033[0m")
    # 多个字符串连接
    if " % " in param:
        replace_pattern_res = replace_pattern.match(param)
        if replace_pattern_res:
            tuple_replace_pattern_res = tuple_replace_pattern.match(param)
            if tuple_replace_pattern_res:
                if debug:
                    print("\033[34m[*] Need further judge: multi % str format\033[0m")
                original_str = tuple_replace_pattern_res.group(1)

                if "%s" in original_str or "{}" in original_str:
                    original_str = original_str.replace("%s", "")
                    original_str = original_str.replace("{}", "")

                if judge(original_str, file_location, line_number):
                    return True

                variable_list = tuple_replace_pattern_res.group(2).split(',')
                res = False
                for variable in variable_list:
                    variable = variable.strip()

                    res = res or judge(variable, file_location, line_number)

                    if res:
                        return True

                return False

            else:
                if debug:
                    print("\033[34m[*] Need further judge: single % str format\033[0m")

                original_str = replace_pattern_res.group(1)
                original_str = original_str.rstrip()
                if "%s" in original_str or "{}" in original_str:
                    original_str = original_str.replace("%s", "")
                    original_str = original_str.replace("{}", "")

                variable_name = replace_pattern_res.group(2)
                variable_name = variable_name.strip()

                if variable_name[0] == "(" and variable_name[-1] == ")":
                    variable_name = variable_name[1:-1]

                return judge(original_str, file_location, line_number) or \
                    judge(variable_name, file_location, line_number)

        else:
            return True

    # format 格式化替换
    elif ".format(" in param:
        if debug:
            print("\033[33m[*] Need manual investigation: .format str format\033[0m")
        return True

    # f-string 格式化字符串
    elif "f\'" in param:
        if debug:
            print("\033[33m[*] Need manual investigation: f-string str format\033[0m")
        return True

    elif " if " in param:
        if debug:
            print("\033[33m[*] Need manual investigation: conditional assignment\033[0m")
        return True

    # 函数调用
    elif "(" in param:
        if debug:
            print("\033[33m[*] Need manual investigation: func_call\033[0m")
        return True

    elif "+" in param:
        if debug:
            print("\033[34m[*] Need further judge: str splicing\033[0m")
        parm_list = param.split("+")

        res = False
        for sep_param in parm_list:
            res = res or judge(sep_param, file_location, line_number)
        return res

    else:
        # 字符串常量
        if "[" in param and "]" in param:
            if debug:
                print("\033[33m[*] Need manual investigation: variable index\033[0m")
            return True

        elif ("\"" in param) or ("\'" in param):
            if debug:
                print("\033[32m[*] No risk: str constant\033[0m")
            return False

        # 单个变量名
        else:
            param = param.strip()
            if constant_pattern.match(param):
                if debug:
                    print("\033[32m[*] No risk: declared constant\033[0m")
                return False
            else:
                variable_name_pattern_res = variable_name_pattern.match(param)
                if not variable_name_pattern_res:
                    num_pattern_res = num_pattern.match(param)
                    if num_pattern_res:
                        if debug:
                            print("\033[32m[*] No risk: number constant\033[0m")
                        return False

                    if "." in param:
                        if debug:
                            print("\033[33m[*] Need manual investigation: class property\033[0m")
                        return True
                if debug:
                    print("\033[34m[*] Need further judge: variable name\033[0m")
                status, variable_content, new_line_number = find_variable_content(param, file_location, line_number)
                if status:
                    return judge(variable_content, file_location, new_line_number)
                else:
                    return True


def find_variable_content(param, file_location, line_number):
    param = param.strip()
    new_line_number = line_number

    if debug:
        print("\033[34m[*] Begin to find: " + param + "\033[0m")

    if constant_pattern.match(param):
        return True, param, new_line_number

    variable_content = ""
    front_code_context = get_front_code_context(file_location, line_number)
    length = len(front_code_context)
    front_code_context.reverse()

    param_pattern = re.compile(param + r' = (.*)')

    index = 0

    for line in front_code_context:
        code_line = line[1].strip()
        res = param_pattern.match(code_line)
        if res:
            loop_index = index
            # 命令是否分行
            if code_line[-1] == "," or code_line[-1] == "\\" or code_line[-1] == "(":
                if code_line[-1] == "\\":
                    variable_content += res.group(1)[:-1]
                else:
                    variable_content += res.group(1)

                loop_index -= 1
                code_line = front_code_context[loop_index][1].strip()

                while code_line[-1] == "," or code_line[-1] == "\\" or code_line[-1] == "(":
                    if code_line[-1] == "," or code_line[-1] == "(":
                        variable_content += code_line
                    else:
                        if code_line[:-1].strip()[-1] == '"' \
                                and front_code_context[loop_index - 1][1].strip()[0] == '"':
                            variable_content += code_line[:-1].strip()[:-1]
                            front_code_context[loop_index - 1][1] = front_code_context[loop_index - 1][1].strip()[1:]
                        else:
                            variable_content += code_line[:-1]
                    loop_index -= 1
                    code_line = front_code_context[loop_index][1].strip()
                variable_content += code_line
            else:
                variable_content += res.group(1)
            new_line_number = str(int(new_line_number) - index)
            break
        index += 1

    if index < length:
        if debug:
            print("\033[34m[*] Found by front_contxet: " + variable_content + "\033[0m")
        return True, variable_content, new_line_number
    else:
        status, variable_content, new_line_number = deep_search(param, file_location)
        if status:
            if debug:
                print("\033[34m[*] Found by deep_search: " + variable_content + "\033[0m")
            return True, variable_content, new_line_number
        if debug:
            print("\033[33m[*] Not found\033[0m")
        return False, "", new_line_number


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Scan args of os cmd exec funcs and '
                                                 'judge whether there is inject risk.')
    parser.add_argument('-P', '--path', required=True, type=str, help='path of the source code you want to scan')
    parser.add_argument('-D', '--debug', default=True, type=bool, help='whether show parsing process')
    parser.add_argument('-s', '--show', default=False, type=bool, help='whether show risk free func_call code')
    parser.add_argument('-d', '--depth', default='20', type=int, help='The number of rows to search forward for '
                                                                      'parameter values from the function call line')
    args = parser.parse_args()

    root_path = args.path
    debug = args.debug
    show_safe_calls = args.show
    search_depth = int(args.depth)

    cmd_inject_detect()
