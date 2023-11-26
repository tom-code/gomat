package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type MatterInfo struct {
	Clusters map[int]ClusterInfo
}

type ClusterInfo struct {
	Name       string
	Id         int
	Commands   []CommandInfo
	Attributes []AttributeInfo
}

type CommandInfo struct {
	Name string
	Id   int
}
type AttributeInfo struct {
	Name string
	Id   int
}

type CommandXmlDef struct {
	Name string `xml:"name,attr"`
	Id   string `xml:"id,attr"`
}

type CommandListXmlDef struct {
	Command []CommandXmlDef `xml:"command"`
}

type AttributeXmlDef struct {
	Name string `xml:"name,attr"`
	Id   string `xml:"id,attr"`
}

type AttributeListXmlDef struct {
	Attribute []AttributeXmlDef `xml:"attribute"`
}

type ClusterXmlDef struct {
	XMLName    xml.Name            `xml:"cluster"`
	Name       string              `xml:"name,attr"`
	Id         string              `xml:"id,attr"`
	Commands   CommandListXmlDef   `xml:"commands"`
	Attributes AttributeListXmlDef `xml:"attributes"`
}

func symbolize(in string) string {
	s := strings.ReplaceAll(in, " ", "")
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, "/", "")
	return s
}

func process_file(fname string) (ClusterInfo, error) {
	xml_content, err := os.ReadFile(fname)
	var out ClusterInfo
	if err != nil {
		return out, err
	}

	var parsed_xml ClusterXmlDef
	err = xml.Unmarshal(xml_content, &parsed_xml)
	if err != nil {
		return out, err
	}
	log.Printf("%+v\n", parsed_xml)
	out.Name = symbolize(parsed_xml.Name)
	id, err := strconv.ParseUint(parsed_xml.Id, 0, 32)
	if err != nil {
		return out, err
	}
	out.Id = int(id)

	for _, command := range parsed_xml.Commands.Command {
		id, err := strconv.ParseUint(command.Id, 0, 32)
		if err != nil {
			continue
		}
		cmd := CommandInfo{
			Name: symbolize(command.Name),
			Id:   int(id),
		}
		out.Commands = append(out.Commands, cmd)
	}
	deduplicate := map[string]bool{}
	for _, attribute := range parsed_xml.Attributes.Attribute {
		_, duplicit := deduplicate[attribute.Name]
		if duplicit {
			continue
		} else {
			deduplicate[attribute.Name] = true
		}
		id, err := strconv.ParseUint(attribute.Id, 0, 32)
		if err != nil {
			continue
		}
		attr := AttributeInfo{
			Name: symbolize(attribute.Name),
			Id:   int(id),
		}
		out.Attributes = append(out.Attributes, attr)
	}
	return out, nil
}

func writeGoInfo(mi MatterInfo) error {
	f, err := os.Create("../info.go")
	if err != nil {
		return err
	}
	defer f.Close()
	f.WriteString("package symbols\n\n")

	for _, cluster := range mi.Clusters {
		f.WriteString(fmt.Sprintf("const CLUSTER_ID_%s = 0x%x\n", cluster.Name, cluster.Id))
		for _, command := range cluster.Commands {
			f.WriteString(fmt.Sprintf("const COMMAND_ID_%s_%s = %d\n", cluster.Name, command.Name, command.Id))
		}
		for _, attribute := range cluster.Attributes {
			f.WriteString(fmt.Sprintf("const ATTRIBUTE_ID_%s_%s = %d\n", cluster.Name, attribute.Name, attribute.Id))
		}
	}

	f.WriteString("var ClusterNameMap = map[int]string {\n")
	for _, cluster := range mi.Clusters {
		f.WriteString(fmt.Sprintf("  CLUSTER_ID_%s: \"%s\",\n", cluster.Name, cluster.Name))
	}
	f.WriteString("}")

	return nil
}

func process_all() (MatterInfo, error) {
	var mi MatterInfo
	mi.Clusters = map[int]ClusterInfo{}
	files, err := os.ReadDir(xmlPath)
	if err != nil {
		return mi, err
	}
	for _, e := range files {
		fname := filepath.Join(xmlPath, e.Name())
		log.Println(fname)
		c, err := process_file(fname)
		if err != nil {
			log.Println(err)
		}
		mi.Clusters[c.Id] = c
		log.Println(c)
	}
	return mi, nil
}

const xmlPath = "../xml"

func main() {
	mi, err := process_all()
	if err != nil {
		panic(err)
	}
	writeGoInfo(mi)
	jsondata, err := json.MarshalIndent(&mi, "", " ")
	if err != nil {
		panic(err)
	}
	os.WriteFile("../info.json", jsondata, 0666)

}
