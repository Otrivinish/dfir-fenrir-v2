"""Seed threat actor library from MITRE ATT&CK Groups data (subset)."""

# Each entry: name, aliases, description, country_of_origin, motivation,
# associated_techniques (MITRE IDs), typical_targets.
SEED_ACTORS = [
    {
        "name": "APT28",
        "aliases": ["Fancy Bear", "Sofacy", "STRONTIUM", "Pawn Storm", "Sednit"],
        "description": "Russian GRU-linked threat group active since at least 2004. Conducts espionage against government, military, and political targets globally. Known for credential phishing and sophisticated implants.",
        "country_of_origin": "Russia",
        "motivation": "espionage",
        "associated_techniques": [
            "T1566", "T1078", "T1059", "T1003", "T1021", "T1071", "T1547",
            "T1055", "T1027", "T1105", "T1036", "T1560", "T1083", "T1135",
        ],
        "typical_targets": ["Government", "Military", "Political organisations", "Defense", "Media"],
    },
    {
        "name": "APT29",
        "aliases": ["Cozy Bear", "The Dukes", "YTTRIUM", "Midnight Blizzard", "IRON HEMLOCK"],
        "description": "Russian SVR-linked threat group conducting long-term covert espionage. Renowned for patience, stealth, and supply-chain compromise. Responsible for the SolarWinds intrusion.",
        "country_of_origin": "Russia",
        "motivation": "espionage",
        "associated_techniques": [
            "T1566", "T1078", "T1059", "T1003", "T1021", "T1071", "T1547",
            "T1055", "T1090", "T1027", "T1105", "T1036", "T1195", "T1562",
        ],
        "typical_targets": ["Government", "Think tanks", "NGOs", "Technology", "Healthcare"],
    },
    {
        "name": "Lazarus Group",
        "aliases": ["HIDDEN COBRA", "Guardians of Peace", "ZINC", "APT38", "BlueNoroff"],
        "description": "North Korean state-sponsored group conducting espionage, financial theft, and destructive attacks on behalf of the DPRK regime.",
        "country_of_origin": "North Korea",
        "motivation": "financial",
        "associated_techniques": [
            "T1566", "T1059", "T1486", "T1203", "T1083", "T1071", "T1090",
            "T1027", "T1055", "T1105", "T1003", "T1547", "T1485",
        ],
        "typical_targets": ["Financial", "Cryptocurrency", "Defense", "Government", "Media"],
    },
    {
        "name": "APT41",
        "aliases": ["Double Dragon", "BARIUM", "Winnti", "WICKED SPIDER"],
        "description": "Chinese state-sponsored group conducting both espionage for the state and financially motivated cybercrime. Notably exploits public-facing applications.",
        "country_of_origin": "China",
        "motivation": "espionage",
        "associated_techniques": [
            "T1566", "T1190", "T1059", "T1003", "T1021", "T1071", "T1547",
            "T1055", "T1090", "T1027", "T1105", "T1036", "T1562",
        ],
        "typical_targets": ["Healthcare", "Technology", "Telecommunications", "Government", "Finance"],
    },
    {
        "name": "Turla",
        "aliases": ["Snake", "Uroburos", "Waterbug", "VENOMOUS BEAR", "Krypton"],
        "description": "Russian FSB-affiliated group, active since the late 1990s. Operates sophisticated implants over hijacked satellite links and compromised third-party infrastructure.",
        "country_of_origin": "Russia",
        "motivation": "espionage",
        "associated_techniques": [
            "T1566", "T1078", "T1059", "T1003", "T1021", "T1071", "T1090",
            "T1027", "T1055", "T1547", "T1036", "T1560",
        ],
        "typical_targets": ["Government", "Military", "Embassies", "Research", "Defense"],
    },
    {
        "name": "Sandworm",
        "aliases": ["VOODOO BEAR", "Telebots", "BlackEnergy", "Seashell Blizzard"],
        "description": "Russian GRU Unit 74455. Responsible for destructive attacks on Ukrainian power grid, NotPetya, and Olympic Destroyer. The most destructive threat group on record.",
        "country_of_origin": "Russia",
        "motivation": "destructive",
        "associated_techniques": [
            "T1566", "T1059", "T1486", "T1561", "T1490", "T1071", "T1021",
            "T1195", "T1078", "T1027", "T1036",
        ],
        "typical_targets": ["Critical infrastructure", "Energy", "Government", "Media", "Financial"],
    },
    {
        "name": "APT10",
        "aliases": ["Stone Panda", "MenuPass", "POTASSIUM", "Cloud Hopper"],
        "description": "Chinese cyber espionage group known for Operation Cloud Hopper — large-scale compromise of managed service providers to reach their clients across multiple sectors.",
        "country_of_origin": "China",
        "motivation": "espionage",
        "associated_techniques": [
            "T1566", "T1078", "T1059", "T1003", "T1021", "T1071", "T1560",
            "T1090", "T1027", "T1105",
        ],
        "typical_targets": ["Managed service providers", "Government", "Healthcare", "Defense", "Finance"],
    },
    {
        "name": "FIN7",
        "aliases": ["Carbanak", "ELBRUS", "Carbon Spider", "Sangria Tempest"],
        "description": "Financially motivated Eastern European group targeting the retail, restaurant, and hospitality sectors. Pioneered spear-phishing with malicious documents and point-of-sale malware.",
        "country_of_origin": "Eastern Europe",
        "motivation": "financial",
        "associated_techniques": [
            "T1566", "T1059", "T1003", "T1021", "T1071", "T1027", "T1543",
            "T1547", "T1055", "T1113",
        ],
        "typical_targets": ["Retail", "Restaurant", "Hospitality", "Financial"],
    },
    {
        "name": "Kimsuky",
        "aliases": ["Velvet Chollima", "THALLIUM", "Emerald Sleet", "Black Banshee"],
        "description": "North Korean intelligence-gathering group focused on Korean peninsula policy, sanctions, and nuclear matters. Known for spear-phishing and browser-based credential theft.",
        "country_of_origin": "North Korea",
        "motivation": "espionage",
        "associated_techniques": [
            "T1566", "T1059", "T1003", "T1071", "T1113", "T1056", "T1027",
            "T1547", "T1105",
        ],
        "typical_targets": ["Government", "Think tanks", "Research", "Nuclear", "Defense"],
    },
    {
        "name": "APT32",
        "aliases": ["OceanLotus", "SeaLotus", "BISMUTH", "Canvas Cyclone"],
        "description": "Vietnamese state-linked group targeting foreign governments, journalists, and corporations to advance national interests and acquire competitive intelligence.",
        "country_of_origin": "Vietnam",
        "motivation": "espionage",
        "associated_techniques": [
            "T1566", "T1059", "T1003", "T1021", "T1071", "T1543", "T1027",
            "T1547", "T1055",
        ],
        "typical_targets": ["Government", "Media", "NGOs", "Technology", "Manufacturing"],
    },
    {
        "name": "MuddyWater",
        "aliases": ["MERCURY", "Static Kitten", "Mango Sandstorm", "Cobalt Ulster"],
        "description": "Iranian MOIS-linked group conducting espionage in the Middle East, Europe, and North America. Uses PowerShell-based tooling and living-off-the-land techniques.",
        "country_of_origin": "Iran",
        "motivation": "espionage",
        "associated_techniques": [
            "T1566", "T1059", "T1003", "T1071", "T1021", "T1543", "T1027",
            "T1036", "T1105",
        ],
        "typical_targets": ["Government", "Telecommunications", "Energy", "Financial"],
    },
    {
        "name": "APT33",
        "aliases": ["Elfin", "HOLMIUM", "Peach Sandstorm", "Refined Kitten"],
        "description": "Iranian group targeting aerospace, energy, and petrochemical sectors in Saudi Arabia, South Korea, and the United States for espionage and possible pre-positioning.",
        "country_of_origin": "Iran",
        "motivation": "espionage",
        "associated_techniques": [
            "T1566", "T1059", "T1003", "T1071", "T1021", "T1547", "T1027",
            "T1105", "T1036",
        ],
        "typical_targets": ["Aerospace", "Energy", "Petrochemical", "Government"],
    },
    {
        "name": "Equation Group",
        "aliases": ["EQGRP", "Tilded Team"],
        "description": "Highly sophisticated threat actor widely attributed to the NSA/TAO. Known for interdiction attacks, firmware implants (EquationDrug/GrayFish), and the ExtraBacon exploit.",
        "country_of_origin": "United States",
        "motivation": "espionage",
        "associated_techniques": [
            "T1190", "T1059", "T1003", "T1071", "T1090", "T1027", "T1055",
            "T1547", "T1542",
        ],
        "typical_targets": ["Government", "Military", "Telecommunications", "Financial", "Research"],
    },
    {
        "name": "LAPSUS$",
        "aliases": ["DEV-0537", "Strawberry Tempest"],
        "description": "Loosely organised extortion group known for social engineering of helpdesks and MFA fatigue attacks to compromise cloud environments of large tech companies.",
        "country_of_origin": "Unknown",
        "motivation": "financial",
        "associated_techniques": [
            "T1566", "T1078", "T1621", "T1552", "T1530", "T1059", "T1136",
        ],
        "typical_targets": ["Technology", "Telecommunications", "Gaming", "Government"],
    },
    {
        "name": "Scattered Spider",
        "aliases": ["UNC3944", "Roasted 0ktapus", "Scatter Swine", "Muddled Libra"],
        "description": "English-speaking threat group specialising in SIM-swapping, MFA fatigue, and social engineering of IT helpdesks to gain privileged access to cloud and identity platforms.",
        "country_of_origin": "Unknown",
        "motivation": "financial",
        "associated_techniques": [
            "T1566", "T1621", "T1078", "T1059", "T1552", "T1530", "T1136",
            "T1556",
        ],
        "typical_targets": ["Technology", "Telecommunications", "Hospitality", "Finance"],
    },
    {
        "name": "Conti",
        "aliases": ["WIZARD SPIDER", "Gold Ulrick"],
        "description": "Russian-linked ransomware-as-a-service operation. Ran one of the most prolific and ruthless ransomware programs before dissolving in 2022. Pioneered the double-extortion model.",
        "country_of_origin": "Russia",
        "motivation": "ransomware",
        "associated_techniques": [
            "T1566", "T1078", "T1059", "T1486", "T1490", "T1021", "T1003",
            "T1027", "T1135",
        ],
        "typical_targets": ["Healthcare", "Government", "Critical infrastructure", "Manufacturing"],
    },
    {
        "name": "LockBit",
        "aliases": ["BITWISE SPIDER", "Gold Mystic"],
        "description": "One of the most prolific ransomware-as-a-service operations. Operates a structured affiliate program and publishes stolen data on a dedicated leak site.",
        "country_of_origin": "Unknown",
        "motivation": "ransomware",
        "associated_techniques": [
            "T1566", "T1078", "T1059", "T1486", "T1490", "T1021", "T1027",
        ],
        "typical_targets": ["Manufacturing", "Professional services", "Healthcare", "Government"],
    },
    {
        "name": "REvil",
        "aliases": ["Sodinokibi", "PINCHY SPIDER", "Gold Southfield"],
        "description": "Ransomware-as-a-service group responsible for the Kaseya VSA and JBS attacks. Known for high ransom demands and sophisticated supply-chain intrusions.",
        "country_of_origin": "Russia",
        "motivation": "ransomware",
        "associated_techniques": [
            "T1566", "T1078", "T1059", "T1486", "T1490", "T1027", "T1021",
            "T1195",
        ],
        "typical_targets": ["Food supply", "Technology", "Legal", "Manufacturing", "MSP"],
    },
    {
        "name": "Cl0p",
        "aliases": ["TA505", "GRACEFUL SPIDER", "Gold Tahoe"],
        "description": "Financially motivated group operating the Cl0p ransomware. Exploits zero-days in managed file transfer (MFT) solutions including GoAnywhere and MOVEit.",
        "country_of_origin": "Russia",
        "motivation": "ransomware",
        "associated_techniques": [
            "T1566", "T1190", "T1059", "T1486", "T1490", "T1021", "T1048",
        ],
        "typical_targets": ["Healthcare", "Finance", "Legal", "Government", "Education"],
    },
    {
        "name": "DarkSide",
        "aliases": ["Carbon Spider (affiliate)", "CARBON SPIDER"],
        "description": "Ransomware group responsible for the Colonial Pipeline attack in 2021. Operated a RaaS model and claimed to avoid hospitals and schools. Rebranded as BlackMatter after shutdown.",
        "country_of_origin": "Russia",
        "motivation": "ransomware",
        "associated_techniques": [
            "T1566", "T1078", "T1059", "T1486", "T1490", "T1083", "T1021",
            "T1027",
        ],
        "typical_targets": ["Energy", "Critical infrastructure", "Manufacturing"],
    },
    {
        "name": "BlackCat",
        "aliases": ["ALPHV", "Noberus"],
        "description": "Ransomware group operating a Rust-based payload (ALPHV/BlackCat). Sophisticated affiliate program, triple extortion, and attacks on healthcare and critical infrastructure.",
        "country_of_origin": "Russia",
        "motivation": "ransomware",
        "associated_techniques": [
            "T1566", "T1078", "T1059", "T1486", "T1490", "T1021", "T1003",
            "T1027", "T1562",
        ],
        "typical_targets": ["Healthcare", "Critical infrastructure", "Finance", "Government"],
    },
    {
        "name": "APT1",
        "aliases": ["Comment Crew", "Comment Panda", "Byzantine Candor", "TG-8223"],
        "description": "Chinese PLA Unit 61398. Mandiant's 2013 APT1 report exposed large-scale industrial espionage targeting English-speaking organisations across 20 industries.",
        "country_of_origin": "China",
        "motivation": "espionage",
        "associated_techniques": [
            "T1566", "T1059", "T1003", "T1021", "T1071", "T1560", "T1074",
            "T1027", "T1105",
        ],
        "typical_targets": ["Aerospace", "Energy", "Defense", "IT", "Telecommunications"],
    },
    {
        "name": "APT3",
        "aliases": ["Gothic Panda", "UPS Team", "TG-0110", "Buckeye"],
        "description": "Chinese cyber espionage group known for using 0-day exploits in Internet Explorer and Flash Player. Reportedly associated with China's MSS.",
        "country_of_origin": "China",
        "motivation": "espionage",
        "associated_techniques": [
            "T1566", "T1190", "T1059", "T1003", "T1021", "T1071", "T1036",
            "T1027",
        ],
        "typical_targets": ["Defense", "Aerospace", "Technology", "Government"],
    },
    {
        "name": "Volt Typhoon",
        "aliases": ["BRONZE SILHOUETTE", "Vanguard Panda", "UNC3236", "Dev-0391"],
        "description": "Chinese state-sponsored group pre-positioning in US critical infrastructure. Distinguished by heavy use of living-off-the-land techniques and avoiding custom malware.",
        "country_of_origin": "China",
        "motivation": "espionage",
        "associated_techniques": [
            "T1078", "T1059", "T1021", "T1036", "T1083", "T1049", "T1057",
            "T1571", "T1090",
        ],
        "typical_targets": ["Communications", "Energy", "Transportation", "Water", "Government"],
    },
    {
        "name": "Hafnium",
        "aliases": ["BRONZE LOCKSMITH", "Silk Typhoon"],
        "description": "Chinese state-sponsored group that exploited four Microsoft Exchange Server zero-days in 2021 (ProxyLogon). Targets infectious disease researchers and defence contractors.",
        "country_of_origin": "China",
        "motivation": "espionage",
        "associated_techniques": [
            "T1190", "T1059", "T1003", "T1021", "T1071", "T1505",
            "T1027", "T1560",
        ],
        "typical_targets": ["Research", "Defense", "Law firms", "Government", "NGOs"],
    },
]


async def seed_threat_actors(db) -> int:
    """Idempotently insert built-in threat actors. Returns count of rows inserted."""
    import uuid as _uuid
    from sqlalchemy import select
    from models import ThreatActor

    inserted = 0
    for spec in SEED_ACTORS:
        exists = (await db.execute(
            select(ThreatActor).where(ThreatActor.name == spec["name"])
        )).scalar_one_or_none()
        if exists:
            continue
        db.add(ThreatActor(
            id=_uuid.uuid4(),
            name=spec["name"],
            aliases=spec["aliases"],
            description=spec["description"],
            country_of_origin=spec["country_of_origin"],
            motivation=spec["motivation"],
            associated_techniques=spec["associated_techniques"],
            typical_targets=spec["typical_targets"],
            is_system=True,
        ))
        inserted += 1

    if inserted:
        await db.commit()

    return inserted
