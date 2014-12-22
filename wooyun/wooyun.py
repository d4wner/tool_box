#!/usr/bin/env python
#coding=utf-8
import urllib2
import urllib
import re
from BeautifulSoup import BeautifulSoup
import time
import sys
import base64
import linecache
reload(sys) 
sys.setdefaultencoding('utf8')

proxy_count = 0

def url_open(url):
    #postDict = {'q' : keyword}
    #postData = urllib.urlencode(postDict);
    request = urllib2.Request(url)
    request.add_header("Accept", "*/*")
    request.add_header('Referer', "http://www.wooyun.org/")
    request.add_header("Accept-Language", "zh-cn")
    request.add_header("User-Agent", "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; MyIE9; BTRS123646; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)")
    opener = urllib2.build_opener()
    f = opener.open(request).read()
    return f

def proxy_test(ip):
    for proxy_ip in open('proxy.txt','r'):
        proxy_support = urllib2.ProxyHandler({'http':proxy_ip.strip()})
        opener = urllib2.build_opener(proxy_support, urllib2.
        HTTPHandler)
        urllib2.install_opener(opener)
        content = urllib2.urlopen('http://www.wooyun.org').read()
        #print content
        if content:
            return True


def proxy(url,count):
    #for proxy_ip in open('proxy.txt','r'):
    linecache.clearcache()
    proxy_ip = linecache.getline('proxy.txt',count)
    print proxy_ip+"=========="
    proxy_support = urllib2.ProxyHandler({'http':proxy_ip.strip()})  
    opener = urllib2.build_opener(proxy_support, urllib2.
    HTTPHandler)  
    urllib2.install_opener(opener)  
    content = urllib2.urlopen(url).read() 
    return content
    #print proxy_ip



def spe_read(string,keyword):
    match = re.search(keyword,string,re.I)
    if match:
        return True


#def url_open(url):
#    print "==="+url+"==="
#    resp = urllib2.urlopen(url).read()
#    print "+++"+resp+"+++"
#    return resp

def page_count(resp):
    match = re.search(r"条记录.*页", resp)
    count = re.search(r"\d+", match.group(0))
    print count.group(0)
    return count.group(0)

def read_vulns(resp):
    b_resp = BeautifulSoup(resp)
    table = b_resp.findAll(attrs={"class":"listTable"})[1]
    #print table
    tbody = table.find('tbody')
    trs = tbody.findAll('tr')

    for tr in trs:
        td =  tr.find('td')
        #print td
        #print url.split('/')[-1]
        vul_url = td.find('a')['href']
        vul_type = url.split('/')[-1]
        #print vul_type
        print urllib.unquote(vul_type).strip()   #corp_vul_type
        #print vul_type+"======"
        ths = tr.findAll('th')      
        print ths[0].text             #corp_vul_date
        print td.find('a').text       #corp_vul_name
        #print ths[1].text
        print "http://www.wooyun.org"+vul_url   
        vul_url = "http://www.wooyun.org"+vul_url  #corp_vul_url
        read_vuln_page(vul_url)
        #for th in ths:
        #print th.find('a').text

def read_vuln_page(vul_url):
    resp = urllib2.urlopen(vul_url).read()
    b_resp = BeautifulSoup(resp)
    detail = b_resp.findAll(attrs={"class":"detail"})[2]
    print detail.text    # vul_detail
    print "===="
    return resp




if __name__ == "__main__":

    for url in open('url.txt','r'):
        url = url.strip()
        if spe_read(url,'http'):
            #url = "http://www.wooyun.org/corps/%E9%AA%91%E5%A3%AB%E4%BA%BA%E6%89%8D%E7%B3%BB%E7%BB%9F"
            resp = url_open(url)
            count = int(page_count(resp))
            # url+"/page/2"
            for i in range(1,count+1):
                per_url = url+"/page/"+str(i)
                resp = url_open(per_url)
                read_vulns(resp)
        else:
            if not proxy_test:
                print "[x] Proxy_ip may exist some problems!"
            print "[+] Proxy_ip should be normal."
            keyword = base64.b64encode(url)
            keyword = urllib.quote(keyword)
            #f = search_header(url)
            vuln_url = 'http://www.wooyun.org/searchbug.php?q='+keyword
            print vuln_url
            resp = url_open(vuln_url)
            time.sleep(2)
            #resp = url_open('http://www.wooyun.org/searchbug.php?q='+keyword)
            #print resp
            print resp
            count = int(page_count(resp))
            print count
            for i in range(1,count+1):
                print i
                #resp = url_open('http://www.wooyun.org/searchbug.php?q='+keyword+'&pNO='+str(i))
                if proxy_count < 18:
                    proxy_count = proxy_count + 1
                else:
                    proxy_count = 1
                per_page_url = 'http://www.wooyun.org/searchbug.php?q='+keyword+'&pNO='+str(i)
                time.sleep(2)
                #print url
                #print url
                #print proxy_count
                resp = proxy(per_page_url,proxy_count)
                #print resp
                b_resp = BeautifulSoup(resp)
                alinks = b_resp.findAll('a', attrs={'class':'atitle'})
                for alink in alinks:
                    #print alink
                    #if url in alink.text:
                    #print alink.text
                    #print url
                    if spe_read(alink.text,url):
                        vul_url = "http://www.wooyun.org"+alink['href']
                        print url                       #keyword_vul_type
                        print vul_url                   #keyword_vul_url
                        print alink.text                #keyword_vul_name
                        keyword_page_resp = read_vuln_page(vul_url)
                        match = re.search(r'\s+\d+-\d+-\d+\s\d+:\d+',resp)
                        date = re.search(r'\d+-\d+-\d+',match.group(0))
                        print date.group(0)             #keyword_vul_date



