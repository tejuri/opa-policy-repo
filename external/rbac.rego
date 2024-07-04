package com.optum.eimp.patients

import future.keywords.if
import future.keywords.in

default deny = false

authorization = result if {
	result := {
		"deny": deny,
		"enforcement": enforcement,
	}
}

deny if {
	input.resource.type = "Patients"
	has_required_role_permission
	is_offshore
}

claims := payload if {
	[_, payload, _] := io.jwt.decode(input.jwt)
}

enforcement := {
	"rowLevel": rowFilter,
	"columnLevel": columnMasking,
}

# Extract the policy IDs where offshore_restricted is 1
restricted_policy_ids := {policy.policy_id | policy := data.mysql[_]; policy.offshore_restricted == 1}

rowFilter[enforcement] {
	deny
	allowed_roles := {"EIMP_UI_UHG_ORGADMIN_PROD"}
	count(allowed_roles & user_roles_set) != 0
	enforcement := restricted_policy_ids
}

columnMasking[enforcement] {
	deny

	#     not contains(grants, "viewphi")
	enforcement := "NO_PHI"
}

user_roles_set := {x |
	x := claims.role[_]
}

has_required_role_permission if {
	# Check allowed role
	allowed_roles := {"EIMP_UI_UHG_IMDM_READONLY_PROD", "EIMP_UI_UHG_ORGADMIN_PROD"}
	count(allowed_roles & user_roles_set) != 0
}

contains(permissions, elem) if {
	permissions[_] = elem
}

countries := {ent.country | ent := data.entitlement[_]; ent.mail == claims.email}

is_offshore if {
	not "IND" in countries
}
