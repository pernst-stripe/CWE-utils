#!/usr/bin/env groovy

import java.util.regex.*
import javax.xml.xpath.*
import javax.xml.parsers.DocumentBuilderFactory
import groovy.json.JsonSlurper

if (args.length != 1) {
    System.err.println 'Usage: nvd-cwe.groovy nvdcve.json'
    System.exit(1)
}

def getCweName(doc, xpath, cache, id) {
    if (!cache[id]) {
        org.w3c.dom.NodeList nl = xpath.evaluate("/Weakness_Catalog/Weaknesses/Weakness[@ID='$id']/@Name", doc, XPathConstants.NODESET)
        if (nl.getLength() == 1) {
            cache[id] = nl.item(0).getValue().trim()
        } else {
            cache[id] = ''
        }
    }
    return cache[id]
}

def builder = DocumentBuilderFactory.newInstance().newDocumentBuilder()
def xpath = XPathFactory.newInstance().newXPath()

def doc = builder.parse(new File('cwe-699-v4.15.xml')).documentElement
//def doc = builder.parse(new File('cwe-1000-v4.11.xml')).documentElement

def cwePattern = Pattern.compile('CWE-([0-9]+)')

def nvd = new JsonSlurper().parseFile(new File(args[0]), 'UTF-8')
def cache = [:]
for (record : nvd.CVE_Items) {
    def cve = record.cve
    def cwe = cve.problemtype.problemtype_data.description.value[0][0]
    if (cwe) {
        def matcher = cwePattern.matcher(cwe)
        if (matcher.find()) {
            def cwe_id = Integer.parseInt(matcher.group(1))
            def cwe_name = getCweName(doc, xpath, cache, cwe_id)
            if (cwe_name != '') {
                println "${cve.CVE_data_meta.ID}, ${cwe_id}, \"CWE-${cwe_id}: ${cwe_name.replace('"', '\'')}\", \"${cve.description.description_data.value[0].replace('"', '\'').replace('\n\n','\n').replaceAll('\n$','')}\'
            }
        }
    }
}
