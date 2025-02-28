from langchain.agents import AgentExecutor,create_react_agent,Tool
from langchain_core.prompts import ChatPromptTemplate
from pydantic import BaseModel, Field
from langchain_community.llms import Ollama
from langchain_experimental.utilities import PythonREPL
from langchain_core.prompts import PromptTemplate
from nmapping import Nmapping
from baby_shark import babyshark

template = '''Answer the following questions as best you can. You have access to the following tools:

{tools}

Use the following format:

Question: the input question you must answer
Thought: you should always think about what to do
Action: the action to take, should be one of [{tool_names}]
Action Input: the input to the action
Observation: the result of the action
... (this Thought/Action/Action Input/Observation can repeat N times)
Thought: I now know the final answer
Final Answer: the final answer to the original input question

Begin!

Question: {input}
Thought:{agent_scratchpad}'''

prompt = PromptTemplate.from_template(template)


llm = Ollama(model="deepseek-r1:1.5b")


nmapped = Nmapping()

baby_sharking=babyshark()

host_discovery = Tool(
    name="host_discovery",
    description="this tool is supposed to find the host on the network , call this when its about host discovery",
    func=nmapped.host_discovery,
)


class HostTool(BaseModel):
    code: str = Field(description="this tool is supposed to find the host on the network , call this when its about host discovery")
host_discovery.args_schema = HostTool


port_scan = Tool(
    name="port_scan",
    description="This tool is supposed to find the open ports , call this when you have to look for port",
    func=nmapped.port_scan,
)


class PortTool(BaseModel):
    code: str = Field(description="This tool is supposed to find the open ports , call this when you have to look for port")
port_scan.args_schema = PortTool

service_version_scan = Tool(
    name="service_version_scan",
    description="This tool is supposed to find service version , call this when you have to look for service version",
    func=nmapped.service_version_scan,
)


class ServiceTool(BaseModel):
    code: str = Field(description="This tool is supposed to find service version , call this when you have to look for service version")
service_version_scan.args_schema = ServiceTool

os_detection = Tool(
    name="os_detection",
    description="this tool is used to find the os of the target , call this when you have to look for os",
    func=nmapped.os_detection,
)


class OsTool(BaseModel):
    code: str = Field(description="this tool is used to find the os of the target , call this when you have to look for os")
os_detection.args_schema = OsTool

network_mapping = Tool(
    name="network_mapping",
    description="this tool is used for network mapping , call this when you are in need for network mapping",
    func=nmapped.network_mapping,
)


class network_tool(BaseModel):
    code: str = Field(description="this tool is used for network mapping , call this when you are in need for network mapping")
network_mapping.args_schema = network_tool


script_scan = Tool(
    name="script_scan",
    description="This tool is used for scanning but by passing two argument , target network and the script",
    func=nmapped.script_scan,
)


class script_scan_tool(BaseModel):
    code: str = Field(description="This tool is used for scanning but by passing two argument , target network and the script")
script_scan.args_schema = script_scan_tool


firewall_evasion = Tool(
    name="firewall_evasion",
    description="Call this tool when you have to check for firewall evation on a network ",
    func=nmapped.firewall_evasion,
)


class firewall_evasion_tool(BaseModel):
    code: str = Field(description="Call this tool when you have to check for firewall evation on a network ")
firewall_evasion.args_schema = firewall_evasion_tool

aggressive_scan = Tool(
    name="aggressive_scan",
    description="this tool is particularly meant for aggressive scanning purpose",
    func=nmapped.aggressive_scan,
)


class aggressive_scan_tool(BaseModel):
    code: str = Field(description="this tool is particularly meant for aggressive scanning purpose")
aggressive_scan.args_schema = aggressive_scan_tool

stealth_scan = Tool(
    name="stealth_scan",
    description="this tool is particularly meant for stealth scanning purpose",
    func=nmapped.stealth_scan,
)


class stealth_tool(BaseModel):
    code: str = Field(description="this tool is particularly meant for stealth scanning purpose")
stealth_scan.args_schema = stealth_tool

capture_live = Tool(
    name="capture_live",
    description="when you have to capture live packets on a network , you have to use this tool and it will take the interface as argument",
    func=baby_sharking.capture_live,
)


class capture_live_tool(BaseModel):
    code: str = Field(description="when you have to capture live packets on a network , you have to use this tool and it will take the interface as argument")
capture_live.args_schema = capture_live_tool

filter_packets = Tool(
    name="filter_packets",
    description="when you have to capture live packets on a network , you have to use this tool and it will take the interface as argument and to display based on filters ",
    func=baby_sharking.filter_packets,
)


class filter_packets_tool(BaseModel):
    code: str = Field(description="when you have to capture live packets on a network , you have to use this tool and it will take the interface as argument and to display based on filters ")
filter_packets.args_schema = filter_packets_tool

extract_ip_addresses = Tool(
    name="extract_ip_addresses",
    description="this tool will be handy while you have to extract the ip address of the captured packages",
    func=baby_sharking.extract_ip_addresses,
)


class extract_ip_addresses_tool(BaseModel):
    code: str = Field(description="this tool will be handy while you have to extract the ip address of the captured packages")
baby_sharking.args_schema = extract_ip_addresses_tool

detect_http_requests = Tool(
    name="detect_http_requests",
    description="when you have to capture live packets on a network , you have to use this tool and it will take the interface as argument and to display based on filters particularly when its about https",
    func=baby_sharking.detect_http_requests,
)


class detect_http_requests_tool(BaseModel):
    code: str = Field(description="when you have to capture live packets on a network , you have to use this tool and it will take the interface as argument and to display based on filters  particularly when its about hhtps")
detect_http_requests.args_schema = detect_http_requests_tool

detect_dns_queries = Tool(
    name="detect_dns_queries",
    description="when you have to capture live packets on a network , you have to use this tool and it will take the interface as argument and to display based on filters  particularly when its about dns",
    func=baby_sharking.detect_dns_queries,
)


class detect_dns_queries_tool(BaseModel):
    code: str = Field(description="when you have to capture live packets on a network , you have to use this tool and it will take the interface as argument and to display based on filters  particularly when its about dns")
detect_dns_queries.args_schema = detect_dns_queries_tool


agent = create_react_agent(
    llm=llm,
    tools=[host_discovery,port_scan,detect_dns_queries,detect_http_requests,extract_ip_addresses,filter_packets,capture_live,stealth_scan,aggressive_scan,firewall_evasion,script_scan,network_mapping,os_detection,service_version_scan,port_scan],
    prompt=prompt,
)

agent_executor = AgentExecutor(agent=agent, tools=[host_discovery,port_scan,detect_dns_queries,detect_http_requests,extract_ip_addresses,filter_packets,capture_live,stealth_scan,aggressive_scan,firewall_evasion,script_scan,network_mapping,os_detection,service_version_scan,port_scan], verbose=True,handle_parsing_errors=True)

print(agent_executor.invoke({"input": "what is LangChain?"}))

