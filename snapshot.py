# -*- coding: utf-8 -*-
"""
Fallback snapshot data for the IBM JDK / Semeru Runtimes CVE report.
Compiled 2026-07-14 from IBM Security Bulletins. Used only when the live
scrape in generate.py fails, so the page always rebuilds successfully.

Each batch: (advisory_title, info_url, advisory_date, rows)
  rows = [ (cve_id, cvss_float, {jdk_line: fix_version}, notes) ]
"""

SEMERU = [
 ("IBM Security Update May 2026","https://www.ibm.com/support/pages/node/7272269","2026-05-07",[
   ("CVE-2026-6918",8.2,{"8":"8.0.492.0","11":"11.0.31.0","17":"17.0.19.0","21":"21.0.11.0","25":"25.0.3.0","26":"26.0.1.0"},"Applicable on Linux on x86/PPC/AArch64/Z only"),
 ]),
 ("OpenJDK April 21 2026 Vulnerability Advisory","https://openjdk.org/groups/vulnerability/advisories/2026-04-21","2026-04-21",[
   ("CVE-2026-34282",7.5,{"11":"11.0.31.0","17":"17.0.19.0","21":"21.0.11.0","25":"25.0.3.0","26":"26.0.1.0"},""),
   ("CVE-2026-22016",7.5,{"8":"8.0.492.0","11":"11.0.31.0","17":"17.0.19.0","21":"21.0.11.0","25":"25.0.3.0","26":"26.0.1.0"},""),
   ("CVE-2026-23865",5.3,{"11":"11.0.31.0","17":"17.0.19.0","21":"21.0.11.0","25":"25.0.3.0","26":"26.0.1.0"},""),
   ("CVE-2026-22021",5.3,{"8":"8.0.492.0","11":"11.0.31.0","17":"17.0.19.0","21":"21.0.11.0","25":"25.0.3.0","26":"26.0.1.0"},""),
   ("CVE-2026-22013",5.3,{"8":"8.0.492.0","11":"11.0.31.0","17":"17.0.19.0","21":"21.0.11.0","25":"25.0.3.0","26":"26.0.1.0"},""),
   ("CVE-2026-22018",3.7,{"8":"8.0.492.0"},""),
   ("CVE-2026-22008",3.7,{"25":"25.0.3.0","26":"26.0.1.0"},""),
   ("CVE-2026-34268",2.9,{"8":"8.0.492.0","11":"11.0.31.0","17":"17.0.19.0","21":"21.0.11.0","25":"25.0.3.0","26":"26.0.1.0"},""),
   ("CVE-2026-22007",2.9,{"8":"8.0.492.0","11":"11.0.31.0","17":"17.0.19.0","21":"21.0.11.0","25":"25.0.3.0","26":"26.0.1.0"},""),
 ]),
 ("IBM Security Update January 2026","https://www.ibm.com/support/pages/node/7259431","2026-01-31",[
   ("CVE-2026-1188",6.9,{"8":"8.0.482.0","11":"11.0.30.0","17":"17.0.18.0","21":"21.0.10.0","25":"25.0.2.0"},""),
 ]),
 ("OpenJDK January 20 2026 Vulnerability Advisory","https://openjdk.org/groups/vulnerability/advisories/2026-01-20","2026-01-20",[
   ("CVE-2026-21945",7.5,{"8":"8.0.482.0","11":"11.0.30.0","17":"17.0.18.0","21":"21.0.10.0","25":"25.0.2.0"},""),
   ("CVE-2026-21932",7.4,{"8":"8.0.482.0","11":"11.0.30.0","17":"17.0.18.0","21":"21.0.10.0","25":"25.0.2.0"},"Applicable on Windows and Mac OS only"),
   ("CVE-2026-21933",6.1,{"8":"8.0.482.0","11":"11.0.30.0","17":"17.0.18.0","21":"21.0.10.0","25":"25.0.2.0"},""),
   ("CVE-2026-21925",4.8,{"8":"8.0.482.0","11":"11.0.30.0","17":"17.0.18.0","21":"21.0.10.0","25":"25.0.2.0"},""),
 ]),
 ("OpenJDK October 21 2025 Vulnerability Advisory","https://openjdk.org/groups/vulnerability/advisories/2025-10-21","2025-10-21",[
   ("CVE-2025-53057",5.9,{"8":"8.0.472.0","11":"11.0.29.0","17":"17.0.17.0","21":"21.0.9.0","25":"25.0.1.0"},""),
   ("CVE-2025-53066",7.5,{"8":"8.0.472.0","11":"11.0.29.0","17":"17.0.17.0","21":"21.0.9.0","25":"25.0.1.0"},""),
   ("CVE-2025-61748",3.7,{},"Not applicable to IBM Semeru"),
 ]),
 ("OpenJDK July 15 2025 Vulnerability Advisory","https://openjdk.org/groups/vulnerability/advisories/2025-07-15","2025-07-15",[
   ("CVE-2025-50059",8.6,{"11":"11.0.28.0","17":"17.0.16.0","21":"21.0.8.0"},""),
   ("CVE-2025-50106",8.1,{"8":"8.0.462.0","11":"11.0.28.0","17":"17.0.16.0","21":"21.0.8.0"},"Applicable to IBM Semeru on Mac OS only"),
   ("CVE-2025-30749",8.1,{"8":"8.0.462.0","11":"11.0.28.0","17":"17.0.16.0","21":"21.0.8.0"},"Applicable to IBM Semeru on Mac OS only"),
   ("CVE-2025-30761",5.9,{"8":"8.0.462.0","11":"11.0.28.0"},""),
   ("CVE-2025-30754",4.8,{"8":"8.0.462.0","11":"11.0.28.0","17":"17.0.16.0","21":"21.0.8.0"},""),
 ]),
 ("IBM Security Update May 2025","https://www.ibm.com/support/pages/node/7233415","2025-05-31",[
   ("CVE-2025-2900",7.5,{"8":"8.0.452.0","11":"11.0.27.0","17":"17.0.15.0","21":"21.0.7.0"},""),
   ("CVE-2025-4447",7.0,{"8":"8.0.452.0"},""),
 ]),
 ("OpenJDK April 15 2025 Vulnerability Advisory","https://openjdk.org/groups/vulnerability/advisories/2025-04-15","2025-04-15",[
   ("CVE-2025-21587",7.4,{"8":"8.0.452.0","11":"11.0.27.0","17":"17.0.15.0","21":"21.0.7.0"},""),
   ("CVE-2025-30698",5.6,{"8":"8.0.452.0","11":"11.0.27.0","17":"17.0.15.0","21":"21.0.7.0"},""),
   ("CVE-2025-30691",4.8,{},"Not applicable to IBM Semeru"),
 ]),
 ("OpenJDK January 21 2025 Vulnerability Advisory","https://openjdk.org/groups/vulnerability/advisories/2025-01-21","2025-01-21",[
   ("CVE-2025-21502",4.8,{},"Not applicable to IBM Semeru"),
 ]),
 ("IBM Security Update November 2024","https://www.ibm.com/support/pages/node/7176623","2024-11-30",[
   ("CVE-2024-10917",3.7,{"8":"8.0.432.0","11":"11.0.25.0","17":"17.0.13.0","21":"21.0.5.0","23":"23.0.1.0"},""),
   ("CVE-2024-9143",3.7,{"8":"8.0.432.0","11":"11.0.25.0","17":"17.0.13.0","21":"21.0.5.0","23":"23.0.1.0"},"Applicable on Windows and Mac OS only"),
 ]),
 ("OpenJDK October 15 2024 Vulnerability Advisory","https://openjdk.org/groups/vulnerability/advisories/2024-10-15","2024-10-15",[
   ("CVE-2024-21235",4.8,{},"Not applicable to IBM Semeru"),
   ("CVE-2024-21217",3.7,{"8":"8.0.432.0","11":"11.0.25.0","17":"17.0.13.0","21":"21.0.5.0","23":"23.0.1.0"},""),
   ("CVE-2024-21210",3.7,{},"Not applicable to IBM Semeru"),
   ("CVE-2024-21208",3.7,{"8":"8.0.432.0","11":"11.0.25.0","17":"17.0.13.0","21":"21.0.5.0","23":"23.0.1.0"},""),
 ]),
 ("OpenJDK July 16 2024 Vulnerability Advisory","https://openjdk.org/groups/vulnerability/advisories/2024-07-16","2024-07-16",[
   ("CVE-2024-21147",7.4,{},"Not applicable to IBM Semeru"),
   ("CVE-2024-21145",4.8,{"8":"8.0.422.0","11":"11.0.24.0","17":"17.0.12.0","21":"21.0.4.0","22":"22.0.2.0"},""),
   ("CVE-2024-21140",4.8,{},"Not applicable to IBM Semeru"),
   ("CVE-2024-21144",3.7,{"8":"8.0.422.0","11":"11.0.24.0"},""),
   ("CVE-2024-21138",3.7,{"8":"Fix in progress"},"Not applicable to IBM Semeru"),
   ("CVE-2024-21131",3.7,{"8":"8.0.422.0","11":"11.0.24.0","17":"17.0.12.0","21":"21.0.4.0","22":"22.0.2.0"},""),
 ]),
 ("IBM Security Update May 2024","https://www.ibm.com/support/pages/node/7155291","2024-05-31",[
   ("CVE-2024-3933",5.9,{"8":"8.0.412.0","11":"11.0.23.0","17":"17.0.11.0","21":"21.0.3.0"},"Applicable on zLinux only"),
 ]),
 ("OpenJDK April 16 2024 Vulnerability Advisory","https://openjdk.org/groups/vulnerability/advisories/2024-04-16","2024-04-16",[
   ("CVE-2024-21094",3.7,{},"Not applicable to IBM Semeru"),
   ("CVE-2024-21068",3.7,{},"Not applicable to IBM Semeru"),
   ("CVE-2024-21085",3.7,{"8":"8.0.412.0","11":"11.0.23.0"},""),
   ("CVE-2024-21011",3.7,{},"Not applicable to IBM Semeru"),
   ("CVE-2024-21012",3.7,{"11":"11.0.23.0","17":"17.0.11.0","21":"21.0.3.0"},""),
 ]),
 ("IBM Security Update February 2024","https://www.ibm.com/support/pages/node/7116431","2024-02-29",[
   ("CVE-2024-22361",5.9,{"8":"8.0.402.0","11":"11.0.22.0","17":"17.0.10.0","21":"21.0.2.0"},""),
 ]),
 ("OpenJDK January 16 2024 Vulnerability Advisory","https://openjdk.org/groups/vulnerability/advisories/2024-01-16","2024-01-16",[
   ("CVE-2024-20932",7.5,{"17":"17.0.10.0"},""),
   ("CVE-2024-20952",7.4,{"8":"8.0.402.0","11":"11.0.22.0","17":"17.0.10.0","21":"21.0.2.0"},""),
   ("CVE-2024-20918",7.4,{"8":"8.0.402.0","11":"11.0.22.0","17":"17.0.10.0","21":"21.0.2.0"},""),
   ("CVE-2024-20921",5.9,{"8":"8.0.402.0","11":"11.0.22.0","17":"17.0.10.0","21":"21.0.2.0"},""),
   ("CVE-2024-20919",5.9,{},"Not applicable to IBM Semeru"),
   ("CVE-2024-20926",5.9,{"8":"8.0.402.0","11":"11.0.22.0"},""),
   ("CVE-2024-20945",4.7,{"8":"8.0.402.0","11":"11.0.22.0","17":"17.0.10.0","21":"21.0.2.0"},""),
 ]),
 ("IBM Security Update November 2023","https://www.ibm.com/support/pages/node/7085649","2023-11-29",[
   ("CVE-2023-4807",6.2,{"11":"11.0.21.0","17":"17.0.9.0"},""),
   ("CVE-2023-5676",4.1,{"8":"8.0.392.0","11":"11.0.21.0","17":"17.0.9.0"},""),
 ]),
 ("OpenJDK October 17 2023 Vulnerability Advisory","https://openjdk.org/groups/vulnerability/advisories/2023-10-17","2023-10-17",[
   ("CVE-2023-22081",5.3,{"8":"8.0.392.0","11":"11.0.21.0","17":"17.0.9.0"},""),
   ("CVE-2023-22067",5.3,{"8":"8.0.392.0"},""),
   ("CVE-2023-22025",3.7,{},"Not applicable to IBM Semeru"),
 ]),
 ("OpenJDK July 18 2023 Vulnerability Advisory","https://openjdk.org/groups/vulnerability/advisories/2023-07-18","2023-07-18",[
   ("CVE-2023-22041",5.1,{},"Not applicable to IBM Semeru"),
   ("CVE-2023-22049",3.7,{"8":"8.0.382.0","11":"11.0.20.0","17":"17.0.8.0"},""),
   ("CVE-2023-22045",3.7,{},"Not applicable to IBM Semeru"),
   ("CVE-2023-22044",3.7,{},"Not applicable to IBM Semeru"),
   ("CVE-2023-22036",3.7,{"11":"11.0.20.0","17":"17.0.8.0"},""),
   ("CVE-2023-25193",3.7,{"11":"11.0.19.0","17":"17.0.7.0"},"Fixed in IBM Security Update May 2023"),
   ("CVE-2023-22006",3.1,{"11":"11.0.20.0","17":"17.0.8.0"},""),
 ]),
 ("IBM Security Update May 2023","https://www.ibm.com/support/pages/node/7001271","2023-05-31",[
   ("CVE-2023-25193",7.5,{"11":"11.0.19.0","17":"17.0.7.0"},""),
   ("CVE-2023-2597",7.0,{"8":"8.0.372.0","11":"11.0.19.0","17":"17.0.7.0"},""),
 ]),
 ("OpenJDK April 18 2023 Vulnerability Advisory","https://openjdk.org/groups/vulnerability/advisories/2023-04-18","2023-04-18",[
   ("CVE-2023-21930",7.4,{"8":"8.0.372.0","11":"11.0.19.0","17":"17.0.7.0"},""),
   ("CVE-2023-21967",5.9,{"8":"8.0.372.0","11":"11.0.19.0","17":"17.0.7.0"},""),
   ("CVE-2023-21954",5.9,{},"Not applicable to IBM Semeru"),
   ("CVE-2023-21939",5.3,{"8":"8.0.372.0","11":"11.0.19.0","17":"17.0.7.0"},""),
   ("CVE-2023-21968",3.7,{"8":"8.0.372.0","11":"11.0.19.0","17":"17.0.7.0"},""),
   ("CVE-2023-21937",3.7,{"8":"8.0.372.0","11":"11.0.19.0","17":"17.0.7.0"},""),
   ("CVE-2023-21938",3.7,{"8":"8.0.372.0","11":"11.0.19.0","17":"17.0.7.0"},""),
 ]),
 ("IBM Security Update February 2023","https://www.ibm.com/support/pages/node/6955873","2023-02-28",[
   ("CVE-2022-4304",7.5,{"8":"8.0.362.0","11":"11.0.18.0","17":"17.0.6.0"},"Applicable on Windows and Mac OS only"),
 ]),
 ("OpenJDK January 17 2023 Vulnerability Advisory","https://openjdk.org/groups/vulnerability/advisories/2023-01-17","2023-01-17",[
   ("CVE-2023-21835",5.3,{"11":"11.0.18.0","17":"17.0.6.0"},""),
   ("CVE-2023-21830",5.3,{"8":"8.0.362.0"},""),
   ("CVE-2023-21843",3.7,{"8":"8.0.362.0","11":"11.0.18.0","17":"17.0.6.0"},""),
 ]),
 ("IBM Security Update November 2022","https://www.ibm.com/support/pages/node/6838545","2022-11-30",[
   ("CVE-2022-3676",6.5,{"8":"8.0.352.0","11":"11.0.17.0","17":"17.0.5.0"},""),
 ]),
 ("OpenJDK October 18 2022 Vulnerability Advisory","https://openjdk.org/groups/vulnerability/advisories/2022-10-18","2022-10-18",[
   ("CVE-2022-21628",5.3,{"8":"8.0.352.0","11":"11.0.17.0","17":"17.0.5.0"},""),
   ("CVE-2022-21626",5.3,{"8":"8.0.352.0","11":"11.0.17.0"},""),
   ("CVE-2022-21618",5.3,{"17":"17.0.5.0"},""),
   ("CVE-2022-39399",3.7,{"11":"11.0.17.0","17":"17.0.5.0"},""),
   ("CVE-2022-21624",3.7,{"8":"8.0.352.0","11":"11.0.17.0","17":"17.0.5.0"},""),
   ("CVE-2022-21619",3.7,{"8":"8.0.352.0","11":"11.0.17.0","17":"17.0.5.0"},""),
 ]),
 ("OpenJDK July 19 2022 Vulnerability Advisory","https://openjdk.org/groups/vulnerability/advisories/2022-07-19","2022-07-19",[
   ("CVE-2022-34169",7.5,{"8":"8.0.345.0","11":"11.0.16.0","17":"17.0.4.0","18":"18.0.2.0"},""),
   ("CVE-2022-21541",7.5,{},"Not applicable to IBM Semeru"),
   ("CVE-2022-21549",7.5,{"17":"17.0.4.0"},""),
   ("CVE-2022-21540",7.5,{},"Not applicable to IBM Semeru"),
 ]),
 ("IBM Security Update May 2022","https://www.ibm.com/support/pages/node/6620267","2022-05-31",[
   ("CVE-2021-41041",5.3,{"8":"8.0.332.0","11":"11.0.15.0"},""),
 ]),
 ("OpenJDK April 19 2022 Vulnerability Advisory","https://openjdk.org/groups/vulnerability/advisories/2022-04-19","2022-04-19",[
   ("CVE-2022-21476",7.5,{"8":"8.0.332.0","11":"11.0.15.0","17":"17.0.3.0"},""),
   ("CVE-2022-21449",7.5,{"17":"17.0.3.0","18":"18.0.1.0"},""),
   ("CVE-2022-21496",5.3,{"8":"8.0.332.0","11":"11.0.15.0","17":"17.0.3.0","18":"18.0.1.0"},""),
   ("CVE-2022-21434",5.3,{"8":"8.0.332.0","11":"11.0.15.0","17":"17.0.3.0","18":"18.0.1.0"},""),
   ("CVE-2022-21426",5.3,{"8":"8.0.332.0","11":"11.0.15.0","17":"17.0.3.0","18":"18.0.1.0"},""),
   ("CVE-2022-21443",3.7,{"8":"8.0.332.0","11":"11.0.15.0","17":"17.0.3.0","18":"18.0.1.0"},""),
 ]),
 ("OpenJDK January 18 2022 Vulnerability Advisory","https://openjdk.org/groups/vulnerability/advisories/2022-01-18","2022-01-18",[
   ("CVE-2022-21366",5.3,{"11":"11.0.14.0","17":"17.0.2.0"},""),
   ("CVE-2022-21365",5.3,{"8":"8.0.322.0","11":"11.0.14.0","17":"17.0.2.0"},""),
   ("CVE-2022-21360",5.3,{"8":"8.0.322.0","11":"11.0.14.0","17":"17.0.2.0"},""),
   ("CVE-2022-21349",5.3,{},"Not applicable to IBM Semeru"),
   ("CVE-2022-21341",5.3,{"8":"8.0.322.0","11":"11.0.14.0","17":"17.0.2.0"},""),
   ("CVE-2022-21340",5.3,{"8":"8.0.322.0","11":"11.0.14.0","17":"17.0.2.0"},""),
   ("CVE-2022-21305",5.3,{},"Not applicable to IBM Semeru"),
   ("CVE-2022-21277",5.3,{"11":"11.0.14.0","17":"17.0.2.0"},""),
   ("CVE-2022-21299",5.3,{"8":"8.0.322.0","11":"11.0.14.0","17":"17.0.2.0"},""),
   ("CVE-2022-21296",5.3,{"11":"11.0.14.0","17":"17.0.2.0"},""),
   ("CVE-2022-21282",5.3,{"11":"11.0.14.0","17":"17.0.2.0"},""),
   ("CVE-2022-21294",5.3,{"8":"8.0.322.0","11":"11.0.14.0","17":"17.0.2.0"},""),
   ("CVE-2022-21293",5.3,{"8":"8.0.322.0","11":"11.0.14.0","17":"17.0.2.0"},""),
   ("CVE-2022-21291",5.3,{},"Not applicable to IBM Semeru"),
   ("CVE-2022-21283",5.3,{"11":"11.0.14.0","17":"17.0.2.0"},""),
   ("CVE-2022-21248",3.7,{"8":"8.0.322.0","11":"11.0.14.0","17":"17.0.2.0"},""),
 ]),
 ("IBM Security Update November 2021","https://www.ibm.com/support/pages/node/6522862","2021-11-30",[
   ("CVE-2021-41035",5.3,{"8":"8.0.312.0","11":"11.0.13.0"},""),
 ]),
 ("OpenJDK October 19 2021 Vulnerability Advisory","https://openjdk.org/groups/vulnerability/advisories/2021-10-19","2021-10-19",[
   ("CVE-2021-35567",6.8,{"8":"8.0.312.0","11":"11.0.13.0"},""),
   ("CVE-2021-35550",5.9,{"8":"8.0.312.0","11":"11.0.13.0"},""),
   ("CVE-2021-35586",5.3,{"8":"8.0.312.0","11":"11.0.13.0"},""),
   ("CVE-2021-35578",5.3,{"8":"8.0.312.0","11":"11.0.13.0"},""),
   ("CVE-2021-35564",5.3,{"8":"8.0.312.0","11":"11.0.13.0"},""),
   ("CVE-2021-35561",5.3,{"8":"8.0.312.0","11":"11.0.13.0"},""),
   ("CVE-2021-35559",5.3,{"8":"8.0.312.0","11":"11.0.13.0"},""),
   ("CVE-2021-35556",5.3,{"8":"8.0.312.0","11":"11.0.13.0"},""),
   ("CVE-2021-35565",5.3,{"8":"8.0.312.0","11":"11.0.13.0"},""),
   ("CVE-2021-35603",3.7,{"8":"8.0.312.0","11":"11.0.13.0"},""),
   ("CVE-2021-35588",3.1,{},"Not applicable to IBM Semeru"),
 ]),
 ("OpenJDK July 20 2021 Vulnerability Advisory","https://openjdk.org/groups/vulnerability/advisories/2021-07-20","2021-07-20",[
   ("CVE-2021-2388",7.5,{},"Not applicable to IBM Semeru"),
   ("CVE-2021-2369",4.3,{"8":"8.0.302.0","11":"11.0.12.0","16":"16.0.2.0"},""),
   ("CVE-2021-2432",3.7,{},"Not applicable to IBM Semeru"),
   ("CVE-2021-2341",3.1,{"8":"8.0.302.0","11":"11.0.12.0","16":"16.0.2.0"},""),
 ]),
 ("OpenJDK April 20 2021 Vulnerability Advisory","https://openjdk.org/groups/vulnerability/advisories/2021-04-20","2021-04-20",[
   ("CVE-2021-2161",5.9,{"8":"8.0.292.0","11":"11.0.12.0","16":"16.0.2.0"},"Applicable on Windows only"),
   ("CVE-2021-2163",5.3,{"8":"8.0.292.0","11":"11.0.12.0","16":"16.0.2.0"},""),
 ]),
]

SDK = [
 ("Oracle April 21 2026 CPU","https://www.oracle.com/security-alerts/cpuapr2026.html#AppendixJAVA","2026-04-21",[
   ("CVE-2026-22016",7.5,{"8":"8.0.8.65"},""),
   ("CVE-2026-22003",6.0,{},"Not applicable to IBM JRE/SDK"),
   ("CVE-2026-22021",5.3,{"8":"8.0.8.65"},""),
   ("CVE-2026-22013",5.3,{"8":"8.0.8.65"},""),
   ("CVE-2026-22018",3.7,{"8":"8.0.8.65"},""),
   ("CVE-2026-34268",2.9,{"8":"8.0.8.65"},""),
   ("CVE-2026-22007",2.9,{"8":"8.0.8.65"},""),
 ]),
 ("IBM Security Update January 2026","https://www.ibm.com/support/pages/node/7259436","2026-01-31",[
   ("CVE-2026-1188",6.9,{"8":"8.0.8.55"},""),
 ]),
 ("Oracle January 20 2026 CPU","https://www.oracle.com/security-alerts/cpujan2026.html#AppendixJAVA","2026-01-20",[
   ("CVE-2026-21945",7.5,{"7":"7.1.5.29","8":"8.0.8.60"},""),
   ("CVE-2026-21932",7.4,{"8":"8.0.8.60"},"Applicable on Windows and Mac OS only"),
   ("CVE-2026-21933",6.1,{"7":"7.1.5.29","8":"8.0.8.60"},""),
   ("CVE-2026-21925",4.8,{"7":"7.1.5.29","8":"8.0.8.60"},""),
 ]),
 ("Oracle October 21 2025 CPU","https://www.oracle.com/security-alerts/cpuoct2025.html#AppendixJAVA","2025-10-21",[
   ("CVE-2025-53066",7.5,{"7":"7.1.5.28","8":"8.0.8.55"},""),
   ("CVE-2025-53057",5.9,{"7":"7.1.5.28","8":"8.0.8.55"},""),
   ("CVE-2025-61748",3.7,{},"Not applicable to IBM JRE/SDK"),
 ]),
 ("Oracle July 15 2025 CPU","https://www.oracle.com/security-alerts/cpujul2025.html#AppendixJAVA","2025-07-15",[
   ("CVE-2025-50059",8.6,{},"Not applicable to IBM JRE/SDK"),
   ("CVE-2025-50106",8.1,{"8":"8.0.8.50"},"Applicable on Mac OS only"),
   ("CVE-2025-30749",8.1,{"8":"8.0.8.50"},"Applicable on Mac OS only"),
   ("CVE-2025-30761",5.9,{"8":"8.0.8.50"},""),
   ("CVE-2025-30754",4.8,{"8":"8.0.8.50"},""),
 ]),
 ("IBM Security Update May 2025","https://www.ibm.com/support/pages/node/7233417","2025-05-31",[
   ("CVE-2025-4447",7.0,{"7":"7.1.5.26","8":"8.0.8.45"},""),
 ]),
 ("Oracle April 15 2025 CPU","https://www.oracle.com/security-alerts/cpuapr2025.html#AppendixJAVA","2025-04-15",[
   ("CVE-2025-21587",7.4,{"7":"7.1.5.26","8":"8.0.8.45"},""),
   ("CVE-2025-30698",5.6,{"7":"7.1.5.26","8":"8.0.8.45"},""),
   ("CVE-2025-30691",4.8,{},"Not applicable to IBM JRE/SDK"),
 ]),
 ("Oracle January 21 2025 CPU","https://www.oracle.com/security-alerts/cpujan2025.html#AppendixJAVA","2025-01-21",[
   ("CVE-2025-0509",7.3,{},"Not applicable to IBM JRE/SDK"),
   ("CVE-2025-21502",4.8,{},"Not applicable to IBM JRE/SDK"),
 ]),
 ("IBM Security Update December 2024","https://www.ibm.com/support/pages/node/7177827","2024-12-31",[
   ("CVE-2024-10917",3.7,{"7":"7.1.5.24","8":"8.0.8.35"},""),
 ]),
 ("Oracle October 15 2024 CPU","https://www.oracle.com/security-alerts/cpuoct2024.html#AppendixJAVA","2024-10-15",[
   ("CVE-2024-21235",4.8,{"8":"8.0.8.35"},"Applicable on Solaris, HP-UX and Mac OS only"),
   ("CVE-2024-21217",3.7,{"7":"7.1.5.24","8":"8.0.8.35"},""),
   ("CVE-2024-21210",3.7,{"8":"8.0.8.35"},"Applicable on Solaris, HP-UX and Mac OS only"),
   ("CVE-2024-21208",3.7,{"7":"7.1.5.24","8":"8.0.8.35"},""),
 ]),
 ("IBM Security Update August 2024","https://www.ibm.com/support/pages/node/7165421","2024-08-31",[
   ("CVE-2024-27267",5.9,{"7":"7.1.5.23","8":"8.0.8.30"},""),
 ]),
 ("Oracle July 16 2024 CPU","https://www.oracle.com/security-alerts/cpujul2024.html#AppendixJAVA","2024-07-16",[
   ("CVE-2024-21147",7.4,{"8":"8.0.8.30"},"Applicable on Solaris, HP-UX and Mac OS only"),
   ("CVE-2024-21145",4.8,{"7":"7.1.5.23","8":"8.0.8.30"},""),
   ("CVE-2024-21140",4.8,{"8":"8.0.8.30"},"Applicable on Solaris, HP-UX and Mac OS only"),
   ("CVE-2024-21144",3.7,{"7":"7.1.5.23","8":"8.0.8.30"},""),
   ("CVE-2024-21138",3.7,{"8":"8.0.8.30"},"Applicable on Solaris, HP-UX and Mac OS only"),
   ("CVE-2024-21131",3.7,{"7":"7.1.5.23","8":"8.0.8.30"},""),
 ]),
 ("IBM Security Update May 2024","https://www.ibm.com/support/pages/node/7150727","2024-05-31",[
   ("CVE-2023-38264",5.9,{"7":"7.1.5.22","8":"8.0.8.25"},""),
   ("CVE-2024-3933",5.3,{"8":"8.0.8.25"},"Applicable on zLinux only"),
 ]),
 ("Oracle April 16 2024 CPU","https://www.oracle.com/security-alerts/cpuapr2024.html#AppendixJAVA","2024-04-16",[
   ("CVE-2024-21094",3.7,{"8":"8.0.8.25"},"Applicable on Solaris, HP-UX and Mac OS only"),
   ("CVE-2024-21068",3.7,{},"Not applicable to IBM JRE/SDK"),
   ("CVE-2024-21085",3.7,{"7":"7.1.5.22","8":"8.0.8.25"},""),
   ("CVE-2024-21011",3.7,{"8":"8.0.8.25"},"Applicable on Solaris, HP-UX and Mac OS only"),
   ("CVE-2024-21012",3.7,{},""),
 ]),
 ("IBM Security Update February 2024","https://www.ibm.com/support/pages/node/7116432","2024-02-29",[
   ("CVE-2023-33850",7.5,{"8":"8.0.8.20"},""),
 ]),
 ("Oracle January 16 2024 CPU","https://www.oracle.com/security-alerts/cpujan2024.html#AppendixJAVA","2024-01-16",[
   ("CVE-2024-20932",7.5,{},"Not applicable to IBM JRE/SDK"),
   ("CVE-2024-20952",7.4,{"7":"7.1.5.21","8":"8.0.8.20"},""),
   ("CVE-2024-20918",7.4,{"7":"7.1.5.21","8":"8.0.8.20"},""),
   ("CVE-2024-20921",5.9,{"7":"7.1.5.21","8":"8.0.8.20"},""),
   ("CVE-2024-20919",5.9,{"8":"8.0.8.20"},"Applicable on Solaris, HP-UX and Mac OS only"),
   ("CVE-2024-20926",5.9,{"8":"8.0.8.20"},""),
   ("CVE-2024-20945",4.7,{"8":"8.0.8.20"},""),
 ]),
 ("IBM Security Update November 2023","https://www.ibm.com/support/pages/node/7078433","2023-11-30",[
   ("CVE-2023-5676",4.1,{"7":"7.1.5.20","8":"8.0.8.15"},""),
 ]),
 ("Oracle October 17 2023 CPU","https://www.oracle.com/security-alerts/cpuoct2023.html#AppendixJAVA","2023-10-17",[
   ("CVE-2023-22081",5.3,{"8":"8.0.8.15"},""),
   ("CVE-2023-22067",5.3,{"7":"7.1.5.20","8":"8.0.8.15"},""),
   ("CVE-2023-22025",3.7,{},"Not applicable to IBM JRE/SDK"),
 ]),
 ("IBM Security Update August 2023","https://www.ibm.com/support/pages/node/7017032","2023-08-31",[
   ("CVE-2022-40609",8.1,{"7":"7.1.5.19","8":"8.0.8.5"},""),
 ]),
 ("Oracle July 18 2023 CPU","https://www.oracle.com/security-alerts/cpujul2023.html#AppendixJAVA","2023-07-18",[
   ("CVE-2023-22041",5.1,{},"Not applicable to IBM JRE/SDK"),
   ("CVE-2023-22049",3.7,{"7":"7.1.5.19","8":"8.0.8.10"},""),
   ("CVE-2023-22045",3.7,{"8":"8.0.8.10"},"Applicable on Solaris, HP-UX and Mac OS only"),
   ("CVE-2023-22044",3.7,{},"Not applicable to IBM JRE/SDK"),
   ("CVE-2023-22036",3.7,{},"Not applicable to IBM JRE/SDK"),
   ("CVE-2023-25193",3.7,{},"Not applicable to IBM JRE/SDK"),
   ("CVE-2023-22006",3.1,{},"Not applicable to IBM JRE/SDK"),
 ]),
 ("IBM Security Update June 2023","https://www.ibm.com/support/pages/node/7001663","2023-06-30",[
   ("CVE-2023-2597",7.0,{"7":"7.1.5.18","8":"8.0.8.5"},"Not applicable on Solaris, HP-UX, and Mac OS"),
 ]),
 ("Oracle April 18 2023 CPU","https://www.oracle.com/security-alerts/cpuapr2023.html#AppendixJAVA","2023-04-18",[
   ("CVE-2023-21930",7.4,{"8":"8.0.8.5"},""),
   ("CVE-2023-21967",5.9,{"8":"8.0.8.5"},""),
   ("CVE-2023-21954",5.9,{"8":"8.0.8.5"},"Applicable on Solaris, HP-UX and Mac OS only"),
   ("CVE-2023-21939",5.3,{"7":"7.1.5.18","8":"8.0.8.5"},""),
   ("CVE-2023-21968",3.7,{"7":"7.1.5.18","8":"8.0.8.5"},""),
   ("CVE-2023-21937",3.7,{"7":"7.1.5.18","8":"8.0.8.5"},""),
   ("CVE-2023-21938",3.7,{"7":"7.1.5.18","8":"8.0.8.5"},""),
 ]),
]


def severity(cvss):
    if cvss >= 9.0: return "Critical"
    if cvss >= 7.0: return "High"
    if cvss >= 4.0: return "Medium"
    return "Low"

def _flatten(batches, product):
    out = []
    for title, url, date, rows in batches:
        for cve, cvss, fixes, notes in rows:
            out.append({
                "product": product, "bulletin": title, "bulletinUrl": url,
                "cve": cve, "cveUrl": "https://www.cve.org/CVERecord?id=" + cve,
                "cvss": cvss, "severity": severity(cvss),
                "date": date, "fixes": fixes, "notes": notes,
            })
    return out

def get_snapshot_entries():
    return _flatten(SEMERU, "IBM Semeru Runtimes") + _flatten(SDK, "IBM SDK Java Technology Edition")
