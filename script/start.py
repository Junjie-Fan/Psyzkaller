# !/usr/bin/env python3
# -*- coding:utf-8 -*-

# @author   : fanjunjie
# @time     : 2022/09/23
# @usage    : 从syzkaller的http服务中爬取网页数据
# @para1    : syz-manager的位置
# @para2    : syz-manager用的config的位置
# @para3    : 捕捉的端口
# @para4    : 保存文件的位置


from datetime import datetime
import subprocess
import sys
import time
from tracemalloc import start

def main() :
    """
    使用sys-manager 开启内核fuzz，并且打开计时器，存储每段时间的必要信息，如覆盖率信息，corpus的hash信息
    """
    # param_count = len(sys.argv)
    # if(param_count<4):
    #     print("usage:"+sys.argv[0]+" +path to syz-manager"+" +path to config"+" +port"+" +position you want to store")
    #     exit(1)
    cmd =sys.argv[1]+" -config="+sys.argv[2]
    #print (cmd)
    start_time = datetime.now()
    
    print("hello")

if __name__ == "__main__":
    main()
