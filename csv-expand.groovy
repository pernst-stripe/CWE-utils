#!/usr/bin/env groovy
// Parse a CSV file (as exported from Vulcan) and group all the CWE
// CSV format: CWE, Title, Vuln. Instances, Vuln. Instances, SLA Status

import javax.xml.xpath.*
import javax.xml.parsers.DocumentBuilderFactory

@Grab('com.opencsv:opencsv:5.8')
import com.opencsv.CSVReader

if (args.length != 1) {
    System.err.println 'Usage: csv-expand.groovy file.csv'
    System.exit(1)
}

def getCweName(docs, xpath, id) {
    org.w3c.dom.NodeList nl = xpath.evaluate("/Weakness_Catalog/Weaknesses/Weakness[@ID='$id']/@Name", docs[1000], XPathConstants.NODESET)
    if (nl.getLength() == 1) {
        return nl.item(0).getValue()
    } else {
        org.w3c.dom.NodeList nl2 = xpath.evaluate("/Weakness_Catalog/Categories/Category[@ID='$id']/@Name", docs[699], XPathConstants.NODESET)
        if (nl2.getLength() == 1) {
            return nl2.item(0).getValue()
        } else {
            return ''
        }
    }
}

def display(cols) {
    def builder = DocumentBuilderFactory.newInstance().newDocumentBuilder()
    def xpath = XPathFactory.newInstance().newXPath()

    def docs = [:]
    docs[699] = builder.parse(new File('cwe-699-v4.11.xml')).documentElement
    docs[1000] = builder.parse(new File('cwe-1000-v4.11.xml')).documentElement

    for (int i = 0; i < cols.length; i++) {
        if (cols[i].startsWith('"')) {
            print "${cols[i]}, "
        } else {
            print "\"${cols[i]}\", "
        }
        if (i == 3) {
                def newCol = ''
                if (!cols[3].trim().isEmpty() && !cols[3].startsWith("CWE")) {
                    def cwes = cols[3].split(' > ')
                    def id = Integer.parseInt(cwes[cwes.length - 1])
                    newCol = "=HYPERLINK(\"https://cwe.mitre.org/data/definitions/${id}.html\";\"${getCweName(docs, xpath, id)}\")"
                }
                print "${newCol}, "

            }
    }
    println ''
}

CSVReader reader = new CSVReader(new FileReader(args[0]))
reader.readAll().each{
display( it)
}
