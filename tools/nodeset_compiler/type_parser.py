import codecs
import csv
import json
import xml.etree.ElementTree as etree
import xml.dom.minidom as dom
import copy
import re
from collections import OrderedDict

from .datatypes import QualifiedName, NodeId

try:
    from .opaque_type_mapping import get_base_type_for_opaque as get_base_type_for_opaque_ns0
except ImportError:
    from .nodeset_compiler.opaque_type_mapping import get_base_type_for_opaque as get_base_type_for_opaque_ns0

builtin_types = ["Boolean",  # 1
                 "SByte",    # 2
                 "Byte",     # 3
                 "Int16",    # 4
                 "UInt16",   # 5
                 "Int32",    # 6
                 "UInt32",   # 7
                 "Int64",    # 8
                 "UInt64",   # 9
                 "Float",    # 10
                 "Double",   # 11
                 "String",   # 12
                 "DateTime", # 13
                 "Guid",            # 14
                 "ByteString",      # 15
                 "XmlElement",      # 16
                 "NodeId",          # 17
                 "ExpandedNodeId",  # 18
                 "StatusCode",      # 19
                 "QualifiedName",   # 20
                 "LocalizedText",   # 21
                 "ExtensionObject", # 22
                 "DataValue",       # 23
                 "Variant",         # 24
                 "DiagnosticInfo"   # 25
                 ]

builtin_pointerfree = ["Boolean", "SByte", "Byte", "Int16", "UInt16",
                       "Int32", "UInt32", "Int64", "UInt64", "Float", "Double",
                       "DateTime", "StatusCode", "Guid"]

# DataTypes that are ignored/not generated
excluded_types = [
    # NodeId Types
    "NodeIdType", "TwoByteNodeId", "FourByteNodeId", "NumericNodeId",
    "StringNodeId", "GuidNodeId", "ByteStringNodeId",
    # Node Types
    "InstanceNode", "TypeNode", "Node", "ObjectNode", "ObjectTypeNode", "VariableNode",
    "VariableTypeNode", "ReferenceTypeNode", "MethodNode", "ViewNode", "DataTypeNode"]

rename_types = {"NumericRange": "OpaqueNumericRange"}

# Type aliases
type_aliases = {"CharArray": "String"}

user_opaque_type_mapping = {}  # contains user defined opaque type mapping

class TypeNotDefinedException(Exception):
    pass

def get_base_type_for_opaque(name):
    if name in user_opaque_type_mapping:
        return user_opaque_type_mapping[name]
    return get_base_type_for_opaque_ns0(name)

def get_type_name(xml_type_name):
    [namespace, type_name] = xml_type_name.split(':', 1)
    return [namespace, type_aliases.get(type_name, type_name)]

def get_type_for_name(xml_type_name, types, xmlNamespaces):
    [member_type_name_ns, member_type_name] = get_type_name(xml_type_name)
    resultNs = xmlNamespaces[member_type_name_ns]
    if resultNs == 'http://opcfoundation.org/BinarySchema/':
        resultNs = 'http://opcfoundation.org/UA/'
    if resultNs not in types:
        raise TypeNotDefinedException(f"Unknown namespace: '{resultNs}'")
    if member_type_name not in types[resultNs]:
        raise TypeNotDefinedException(f"Unknown type: '{member_type_name}'")
    return types[resultNs][member_type_name]

def get_type_for_id(id, types):
    strid = str(id)
    for ns_url, ns_types in types.items():
        for t in ns_types.values():
            if str(t.nodeId) == strid:
                return t
    return None


# bsd is the xml definition from the .bsd file
# td is the xml "type-definition" from the nodeset-xml file
class Type:
    def __init__(self, outname, namespaceUri, bsd=None, td=None, name=None):
        self.outname = outname
        self.namespaceUri = namespaceUri
        self.pointerfree = False
        self.members = []
        self.description = ""
        self.nodeId = None
        self.binaryEncodingId = None
        self.xmlEncodingId = None
        if bsd is not None:
            self.name = bsd.get("Name")
        if bsd is not None:
            for child in bsd:
                if child.tag == "{http://opcfoundation.org/BinarySchema/}Documentation":
                    self.description = child.text
                    break
        if td is not None:
            self.name = QualifiedName(td.attributes["Name"].value).name
        if name is not None:
            self.name = name


class BuiltinType(Type):
    def __init__(self, name):
        Type.__init__(self, "types", "http://opcfoundation.org/UA/")
        self.name = name
        self.pointerfree = self.name in builtin_pointerfree
        idx = builtin_types.index(name)
        self.nodeId = NodeId(f"ns=0;i={idx+1}")


class EnumerationType(Type):
    def __init__(self, outname, namespace, bsd=None, td=None, name=None):
        Type.__init__(self, outname, namespace, bsd=bsd, td=td, name=name)
        self.pointerfree = True
        self.elements = OrderedDict()
        self.isOptionSet = False
        self.lengthInBits = 32
        if bsd is not None:
            self.isOptionSet = bsd.get("IsOptionSet", "false") == "true"
            self.lengthInBits = int(bsd.get("LengthInBits", "32"))
        if td is not None:
            self.isOptionSet = td.attributes.get("IsOptionSet", "false") == "true"

        # default values for enumerations (encoded as int32):
        self.strDataType = "UA_Int32"
        self.strTypeKind = "UA_DATATYPEKIND_ENUM"
        self.strTypeIndex = "UA_TYPES_INT32"

        # special handling for OptionSet datatype (bitmask)
        if self.isOptionSet is True:
            if self.lengthInBits <= 8:
                self.strDataType = "UA_Byte"
                self.strTypeKind = "UA_DATATYPEKIND_BYTE"
                self.strTypeIndex = "UA_TYPES_BYTE"
            elif self.lengthInBits <= 16:
                self.strDataType = "UA_UInt16"
                self.strTypeKind = "UA_DATATYPEKIND_UINT16"
                self.strTypeIndex = "UA_TYPES_UINT16"
            elif self.lengthInBits <= 32:
                self.strDataType = "UA_UInt32"
                self.strTypeKind = "UA_DATATYPEKIND_UINT32"
                self.strTypeIndex = "UA_TYPES_UINT32"
            elif self.lengthInBits <= 64:
                self.strDataType = "UA_UInt64"
                self.strTypeKind = "UA_DATATYPEKIND_UINT64"
                self.strTypeIndex = "UA_TYPES_UINT64"
            else:
                raise Exception("Error at EnumerationType() CTOR '" + self.name + "': 'LengthInBits' value '" +
                    self.lengthInBits + "' is not supported")

        # Get the defined values
        if bsd is not None:
            for child in bsd:
                if child.tag == "{http://opcfoundation.org/BinarySchema/}EnumeratedValue":
                    self.elements[child.get("Name")] = child.get("Value")
        if td is not None:
            for field in td.getElementsByTagName("Field"):
                self.elements[field.attributes["Name"].value] = field.attributes["Value"].value


class OpaqueType(Type):
    def __init__(self, outname, namespace, base_type, bsd=None):
        Type.__init__(self, outname, namespace, bsd=bsd)
        self.base_type = base_type


class StructMember:
    def __init__(self, name, member_type, is_array, is_optional):
        self.name = name
        self.member_type = member_type
        self.is_array = is_array
        self.is_optional = is_optional


class StructType(Type):
    def __init__(self, outname, namespace, types, xmlNamespaces=None,
                 bsd=None, td=None, name=None):
        Type.__init__(self, outname, namespace, bsd=bsd, td=td, name=name)
        self.is_recursive = False
        self.is_union = False

        if bsd is not None:
            self._parse_bsd(bsd, types, xmlNamespaces)
        if td is not None:
            self._parse_td(td, types)

        self.pointerfree = True
        for m in self.members:
            if m.is_array or m.is_optional or not m.member_type.pointerfree:
                self.pointerfree = False

    def _parse_td(self, td, types):
        if "IsUnion" in td.attributes and td.attributes["IsUnion"].value == "true":
            self.is_union = True

        fields = td.getElementsByTagName("Field")
        self.members = [StructMember(None, None, False, False) for f in fields]
        for m,f in zip(self.members, fields):
            m.name = f.attributes["Name"].value

            # DataType
            memberid = "ns=0;i=24"
            if "DataType" in f.attributes:
                print(f.attributes["DataType"].value)
                memberid = NodeId(str(f.attributes["DataType"].value))
            m.member_type = get_type_for_id(memberid, types)
            print(memberid)
            assert(m.member_type != None)

            # ValueRank
            if "ValueRank" in f.attributes:
                vr = int(f.attributes["ValueRank"].value)
                if vr == 1:
                    m.is_array = True
                elif vr != -1:
                    raise RuntimeError(f"Type {self.name} has unsupported ValueRank {vr}")

            # IsOptional
            if "IsOptional" in f.attributes and \
               f.attributes["IsOptional"].value == "true":
                m.is_optional = True;

    def _parse_bsd(self, bsd, types, xmlNamespaces):
        length_fields = []
        optional_fields = []
        switch_fields = []

        typename = type_aliases.get(bsd.get("Name"), bsd.get("Name"))

        bt = bsd.get("BaseType")
        self.is_union = bool(bt and get_type_name(bt)[1] == "Union")
        for child in bsd:
            length_field = child.get("LengthField")
            if length_field:
                length_fields.append(length_field)
        for child in bsd:
            switch_field = child.get("SwitchField")
            if switch_field:
                switch_fields.append(switch_field)
        for child in bsd:
            child_type = child.get("TypeName")
            if child_type and get_type_name(child_type)[1] == "Bit":
                optional_fields.append(child.get("Name"))
        for child in bsd:
            if not child.tag == "{http://opcfoundation.org/BinarySchema/}Field":
                continue
            if child.get("Name") in length_fields:
                continue
            if get_type_name(child.get("TypeName"))[1] == "Bit":
                continue
            if self.is_union and child.get("Name") in switch_fields:
                continue
            switch_field = child.get("SwitchField")
            member_is_optional = (switch_field and switch_field in optional_fields)
            member_name = child.get("Name")
            member_name = member_name[:1].lower() + member_name[1:]
            is_array = bool(child.get("LengthField"))

            member_type_name = get_type_name(child.get("TypeName"))[1]
            if member_type_name == typename: # If a type contains itself, use self as member_type
                if not is_array:
                    raise RuntimeError("Type " + typename +  " contains itself as a non-array member")
                member_type = self
                self.is_recursive = True
            else:
                member_type = get_type_for_name(child.get("TypeName"), types, xmlNamespaces)

            self.members.append(StructMember(member_name, member_type, is_array, member_is_optional))


class TypeParser():
    def __init__(self, opaque_map, selected_types, outname, namespaceIndexMap):
        self.opaque_map = opaque_map
        self.selected_types = selected_types
        self.outname = outname
        self.types = OrderedDict()
        self.namespaceIndexMap = namespaceIndexMap

        for builtin in builtin_types:
            self.insert_type(BuiltinType(builtin))

        for f in self.opaque_map:
            user_opaque_type_mapping.update(json.load(f))

        # Read the selected data types
        arg_selected_types = self.selected_types
        self.selected_types = []
        for f in arg_selected_types:
            self.selected_types += list(filter(len, [line.strip() for line in f]))

    @staticmethod
    def merge_dicts(*dict_args):
        """
        Given any number of dicts, shallow copy and merge into a new dict,
        precedence goes to key value pairs in latter dicts.
        """
        result = {}
        for dictionary in dict_args:
            result.update(dictionary)
        return result

    def addTypeFromDefinition(self, td, targetNamespace, id):
        fields = td.getElementsByTagName("Field")
        if len(fields) == 0:
            print(td)
            return
        is_enum = ("Value" in fields[0].attributes)

        if is_enum:
            t = EnumerationType(self.outname, targetNamespace, td=td)
        else:
            t = StructType(self.outname, targetNamespace, self.types, td=td)
        t.nodeId = id
        self.insert_type(t)

    def parseTypeDefinitions(self, outname, xmlDescription):
        def typeReady(element, types, xmlNamespaces):
            "Are all member types defined?"
            parentname = type_aliases.get(element.get("Name"), element.get("Name")) # If a type contains itself, declare that type as available
            for child in element:
                if child.tag == "{http://opcfoundation.org/BinarySchema/}Field":
                    childname = get_type_name(child.get("TypeName"))[1]
                    if childname not in ("Bit", parentname):
                        try:
                            get_type_for_name(child.get("TypeName"), types, xmlNamespaces)
                        except TypeNotDefinedException:
                            # Type is using other types which are not yet loaded, try later
                            return False
            return True

        def unknownTypes(element, types, xmlNamespaces):
            "Return all unknown types (for debugging)"
            unknowns = []
            for child in element:
                if child.tag == "{http://opcfoundation.org/BinarySchema/}Field":
                    try:
                        get_type_for_name(child.get("TypeName"), types, xmlNamespaces)
                    except TypeNotDefinedException:
                        # Type is using other types which are not yet loaded, try later
                        unknowns.append(child.get("TypeName"))
            return unknowns

        def structWithOptionalFields(element):
            "Is this a structure with optional fields?"
            opt_fields = []
            for child in element:
                if child.tag != "{http://opcfoundation.org/BinarySchema/}Field":
                    continue
                typename = child.get("TypeName")
                if typename and get_type_name(typename)[1] == "Bit":
                    if re.match(re.compile('.+Specified'), child.get("Name")):
                        opt_fields.append(child.get("Name"))
                    elif child.get("Name") == "Reserved1":
                        if len(opt_fields) + int(child.get("Length")) != 32:
                            return False
                        break
                    else:
                        return False
                else:
                    return False
            for child in element:
                switchfield = child.get("SwitchField")
                if switchfield and switchfield in opt_fields:
                    opt_fields.remove(switchfield)
            return len(opt_fields) == 0

        def structWithBitFields(element):
            "Is this a structure with bitfields?"
            for child in element:
                typename = child.get("TypeName")
                if typename and get_type_name(typename)[1] == "Bit":
                    return True
            return False

        snippets = OrderedDict()
        xmlDoc = etree.iterparse(xmlDescription, events=['start-ns'])
        xmlNamespaces = dict([node for _, node in xmlDoc])
        targetNamespace = xmlDoc.root.get("TargetNamespace")
        for typeXml in xmlDoc.root:
            if not typeXml.get("Name"):
                continue
            name = typeXml.get("Name")
            snippets[name] = typeXml

        detectLoop = len(snippets) + 1
        while len(snippets) > 0:
            if detectLoop == len(snippets):
                name, typeXml = snippets.popitem()
                raise RuntimeError("Infinite loop detected or type not found while processing types " +
                                   name + ": unknonwn subtype " + str(unknownTypes(typeXml, self.types, xmlNamespaces)) +
                                   ". If the unknown subtype is 'Bit', then maybe a struct with " +
                                   "optional fields is defined wrong in the .bsd-file. If not, maybe " +
                                   "you need to import additional types with the --import flag. " +
                                   "E.g. '--import=UA_TYPES#/path/to/deps/ua-nodeset/Schema/" +
                                   "Opc.Ua.Types.bsd'")
            detectLoop = len(snippets)
            for name, typeXml in list(snippets.items()):
                if (targetNamespace in self.types and name in self.types[targetNamespace]) or name in excluded_types:
                    del snippets[name]
                    continue
                if not typeReady(typeXml, self.types, xmlNamespaces):
                    continue
                if structWithBitFields(typeXml) and not structWithOptionalFields(typeXml):
                    continue
                if name in builtin_types:
                    new_type = BuiltinType(name)
                elif typeXml.tag == "{http://opcfoundation.org/BinarySchema/}EnumeratedType":
                    new_type = EnumerationType(outname, targetNamespace, bsd=typeXml)
                elif typeXml.tag == "{http://opcfoundation.org/BinarySchema/}OpaqueType":
                    new_type = OpaqueType(outname, targetNamespace,
                                          get_base_type_for_opaque(name)['name'],
                                          bsd=typeXml)
                elif typeXml.tag == "{http://opcfoundation.org/BinarySchema/}StructuredType":
                    try:
                        new_type = StructType(outname, targetNamespace, self.types, xmlNamespaces, bsd=typeXml)
                    except TypeNotDefinedException:
                        # Type is using other types which are not yet loaded, try later
                        continue
                else:
                    raise Exception("Type not known")

                self.insert_type(new_type)
                del snippets[name]

    def insert_type(self, t):
        if t.namespaceUri not in self.types:
            self.types[t.namespaceUri] = OrderedDict()

        if t.name in rename_types:
            t.name = rename_types[t.name]

        if t.name not in self.types[t.namespaceUri]:
            self.types[t.namespaceUri][t.name] = t


class CSVBSDTypeParser(TypeParser):
    def __init__(self, opaque_map, selected_types, outname,
                 existing_bsd, type_bsd, type_csv, type_xml, namespaceIndexMap):
        TypeParser.__init__(self, opaque_map, selected_types, outname, namespaceIndexMap)
        self.existing_bsd = existing_bsd # bsd files with existing types not printed again
        self.existing_types_array = set() # existing TYPE_ARRAY from existing_bsd
        self.type_bsd = type_bsd # bsd files with new types
        self.type_csv = type_csv # csv files with nodeids, etc.
        self.type_xml = type_xml # xml files with symbolicNames etc.
        self.existing_types = [] # existing types that shall not be printed
        self._parse_types()

    def _parse_types(self):
        # parse existing types
        for i in self.existing_bsd:
            (outname_import, file_import) = i.split("#")
            self.existing_types_array.add(outname_import)
            outname_import = outname_import.lower()
            if outname_import.startswith("ua_"):
                outname_import = outname_import[3:]
            self.parseTypeDefinitions(outname_import, file_import)

        # all types loaded up to now should be assumed as existing types and therefore
        # no code should be generated
        self.existing_types = copy.deepcopy(self.types)
        # if outname is types (generate typedefinitions for NS0), we still need the BuiltinType
        # therefore remove them from the existing array
        if self.outname == "types":
            for ns in self.types:
                for t in self.types[ns]:
                    if isinstance(self.types[ns][t], BuiltinType):
                        del self.existing_types[ns][t]

        # parse the new types
        for f in self.type_bsd:
            self.parseTypeDefinitions(self.outname, f)

        # create a lookup table with symbolicNames
        table = {}
        for f in self.type_xml:
            table = self.createSymbolicNameTable(f)

        # extend the type definitions with nodeids, etc. from the csv file
        for f in self.type_csv:
            self.parseTypeDescriptions(f, table)

    def createSymbolicNameTable(self, f):
        table = {}
        nodeset_base = open(f.name, "rb")
        fileContent = nodeset_base.read()
        # Remove BOM since the dom parser cannot handle it on python 3 windows
        if fileContent.startswith(codecs.BOM_UTF8):
            fileContent = fileContent.lstrip(codecs.BOM_UTF8)
        fileContent = fileContent.decode("utf-8")

        # Remove the uax namespace from tags. UaModeler adds this namespace to some elements
        fileContent = re.sub(r"<([/]?)uax:(.+?)([/]?)>", "<\\g<1>\\g<2>\\g<3>>", fileContent)

        nodesets = dom.parseString(fileContent).getElementsByTagName("UANodeSet")
        if len(nodesets) == 0 or len(nodesets) > 1:
            raise Exception("contains no or more then 1 nodeset")
        nodeset = nodesets[0]
        dataTypeNodes = nodeset.getElementsByTagName("UADataType")
        for nd in dataTypeNodes:
            if nd.hasAttribute("SymbolicName"):
                # Remove any digit and the colon
                result_string = re.sub(r'\d|:', '', nd.attributes["BrowseName"].nodeValue)
                table[nd.attributes["SymbolicName"].nodeValue] = result_string
        return table

    def parseTypeDescriptions(self, f, table):
        csvreader = csv.reader(f, delimiter=',')
        for row in csvreader:
            if len(row) < 3:
                continue
            if row[2] == "Object":
                # Check if node name ends with _Encoding_DefaultBinary and store
                # the node id in the corresponding DataType
                m = re.match('(.*?)_Encoding_DefaultBinary$', row[0])
                if m:
                    baseType = m.group(1)
                    for ns in self.types:
                        if baseType in self.types[ns]:
                            self.types[ns][baseType].binaryEncodingId = row[1]
                            break

                # Check if node name ends with _Encoding_DefaultXml and store
                # the node id in the corresponding DataType
                m = re.match('(.*?)_Encoding_DefaultXml$', row[0])
                if m:
                    baseType = m.group(1)
                    for ns in self.types:
                        if baseType in self.types[ns]:
                            self.types[ns][baseType].xmlEncodingId = row[1]
                            break
                continue

            if row[2] != "DataType":
                continue

            typeName = row[0]
            if typeName == "BaseDataType":
                typeName = "Variant"
            elif typeName == "Structure":
                typeName = "ExtensionObject"
            if typeName in rename_types:
                typeName = rename_types[typeName]
            # check if typeName is a symbolicName and replace it with the browseName
            if typeName in table:
                typeName = table[typeName]
            for ns in self.types:
                if typeName in self.types[ns]:
                    self.types[ns][typeName].nodeId = row[1]
                    break
