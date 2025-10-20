#!/usr/bin/env python3
"""
Starfleet Characters for Consistent Scenario Generation
======================================================

Shared character data for all event generators to create consistent
attack scenarios featuring Star Trek characters at Starfleet Corp.
"""

import random

# Star Trek characters at Starfleet Corp
STARFLEET_USERS = [
    "jean.picard@starfleet.corp",
    "jordy.laforge@starfleet.corp", 
    "haxorsaurus@starfleet.corp",
    "worf.security@starfleet.corp",
    "data.android@starfleet.corp",
    "deanna.troi@starfleet.corp",
    "beverly.crusher@starfleet.corp",
    "wesley.crusher@starfleet.corp",
    "tasha.yar@starfleet.corp",
    "guinan.bartender@starfleet.corp",
    "james.kirk@starfleet.corp",
    "spock.science@starfleet.corp",
    "leonard.mccoy@starfleet.corp",
    "montgomery.scott@starfleet.corp",
    "nyota.uhura@starfleet.corp",
    "pavel.chekov@starfleet.corp",
    "hikaru.sulu@starfleet.corp",
    "benjamin.sisko@starfleet.corp",
    "kira.nerys@starfleet.corp",
    "julian.bashir@starfleet.corp",
    "jadzia.dax@starfleet.corp",
    "miles.obrien@starfleet.corp",
    "odo.security@starfleet.corp",
    "quark.entrepreneur@starfleet.corp",
    "kathryn.janeway@starfleet.corp",
    "chakotay.commander@starfleet.corp",
    "tuvok.security@starfleet.corp",
    "tom.paris@starfleet.corp",
    "belanna.torres@starfleet.corp",
    "harry.kim@starfleet.corp",
    "seven.of.nine@starfleet.corp",
    "neelix.chef@starfleet.corp",
    "admin@starfleet.corp",
    "security@starfleet.corp",
    "it-support@starfleet.corp"
]

# Department mappings for realistic organizational structure
DEPARTMENTS = {
    "command": ["jean.picard", "james.kirk", "benjamin.sisko", "kathryn.janeway", "chakotay.commander"],
    "security": ["worf.security", "tasha.yar", "odo.security", "tuvok.security"],
    "engineering": ["jordy.laforge", "montgomery.scott", "belanna.torres", "miles.obrien"],
    "science": ["data.android", "spock.science", "jadzia.dax", "seven.of.nine"],
    "medical": ["beverly.crusher", "leonard.mccoy", "julian.bashir"],
    "operations": ["tom.paris", "nyota.uhura", "pavel.chekov", "hikaru.sulu", "harry.kim"],
    "special": ["haxorsaurus", "deanna.troi", "wesley.crusher", "guinan.bartender", "neelix.chef"],
    "admin": ["admin", "security", "it-support"]
}

# Organization info
ORGANIZATION = {
    "domain": "starfleet.corp",
    "name": "Starfleet Corporation", 
    "departments": list(DEPARTMENTS.keys())
}

def get_random_user():
    """Get a random Starfleet user email address"""
    return random.choice(STARFLEET_USERS)

def get_user_by_department(department):
    """Get a random user from a specific department"""
    if department in DEPARTMENTS:
        username = random.choice(DEPARTMENTS[department])
        return f"{username}@starfleet.corp"
    return get_random_user()

def get_username_from_email(email):
    """Extract username from email address"""
    return email.split('@')[0] if '@' in email else email

def get_display_name_from_email(email):
    """Convert email to display name (Jean Picard)"""
    username = get_username_from_email(email)
    return username.replace('.', ' ').title()

def get_compromised_user():
    """Get the primary compromised user for attack scenarios"""
    return "jean.picard@starfleet.corp"  # Captain Picard is the main target

def get_high_value_targets():
    """Get list of high-value targets for attack scenarios"""
    return [
        "jean.picard@starfleet.corp",  # Captain
        "worf.security@starfleet.corp",  # Security Chief
        "data.android@starfleet.corp",  # Operations Officer
        "admin@starfleet.corp",  # System Admin
        "security@starfleet.corp"  # Security Team
    ]