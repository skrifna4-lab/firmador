from lxml import etree
import io

def limpiar_xml(xml_string):
    """Elimina espacios innecesarios que rompen la firma digital"""
    parser = etree.XMLParser(remove_blank_text=True, strip_cdata=False)
    # Aseguramos que el string esté en bytes para el parser
    if isinstance(xml_string, str):
        xml_string = xml_string.encode('utf-8')
    
    return etree.fromstring(xml_string, parser)