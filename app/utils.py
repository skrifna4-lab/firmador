from lxml import etree

def limpiar_xml(xml_string):
    """Limpia espacios en blanco innecesarios para evitar errores de firma"""
    parser = etree.XMLParser(remove_blank_text=True)
    if isinstance(xml_string, str):
        xml_string = xml_string.encode('utf-8')
    return etree.fromstring(xml_string, parser)
