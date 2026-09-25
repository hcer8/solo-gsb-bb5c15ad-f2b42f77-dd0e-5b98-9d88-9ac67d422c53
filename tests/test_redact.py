"""基于 ``x-sensitive`` 的实例脱敏引擎单元测试。

覆盖：对象 / 数组遍历（properties / patternProperties /
additionalProperties / prefixItems / 元组 items / additionalItems）、
本地 ``$ref`` 解析、现代方言（2019-09/2020-12 及形态判定）下 ``$ref``
同级子规则（对象属性 / 数组项 / 组合分支）参与遍历而 Draft-07 及更早
版本忽略同级、oneOf/anyOf 仅遍历校验通过分支、allOf 全分支、
递归引用终止（跳过重复引用不漏同级）、组合分支与 properties 的重复
命中去重、指针转义、原始入参与 schema 不被修改、以及无法解析引用的
异常与 schema 指针。
"""
import pytest

from app import redact

DRAFT_2020_12 = "https://json-schema.org/draft/2020-12/schema"
DRAFT_2019_09 = "https://json-schema.org/draft/2019-09/schema"
DRAFT_7 = "http://json-schema.org/draft-07/schema#"
DRAFT_6 = "http://json-schema.org/draft-06/schema#"
DRAFT_4 = "http://json-schema.org/draft-04/schema#"


def redacted(schema, doc):
    return redact.redact_documents(schema, [doc])["results"][0]


# ---------------------------------------------------------------------------
# 基础对象 / 数组遍历
# ---------------------------------------------------------------------------


def test_replaces_only_sensitive_properties():
    schema = {
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "ssn": {"type": "string", "x-sensitive": True},
        },
    }
    doc = {"name": "alice", "ssn": "111"}
    result = redacted(schema, doc)
    assert result["redacted"] == {"name": "alice", "ssn": "***"}
    assert [(r["instance_pointer"], r["schema_pointer"])
            for r in result["replacements"]] == [
        ("#/ssn", "#/properties/ssn")]
    # 原文不被修改
    assert doc["ssn"] == "111"


def test_non_true_x_sensitive_is_ignored():
    schema = {"properties": {"a": {"x-sensitive": False},
                             "b": {"x-sensitive": "yes"},
                             "c": {}}}
    result = redacted(schema, {"a": 1, "b": 2, "c": 3})
    assert result["redacted"] == {"a": 1, "b": 2, "c": 3}
    assert result["replacements"] == []


def test_array_items_each_redacted():
    schema = {"type": "array", "items": {"x-sensitive": True}}
    result = redacted(schema, ["a", "b", "c"])
    assert result["redacted"] == ["***", "***", "***"]
    assert [r["instance_pointer"] for r in result["replacements"]] == [
        "#/0", "#/1", "#/2"]


def test_nested_objects_and_arrays():
    schema = {
        "properties": {
            "users": {
                "type": "array",
                "items": {
                    "properties": {
                        "email": {"x-sensitive": True},
                        "tags": {"type": "array",
                                 "items": {"x-sensitive": True}},
                    },
                },
            },
        },
    }
    doc = {"users": [{"email": "a@b.c", "tags": ["x"]},
                     {"email": "d@e.f", "tags": []}]}
    result = redacted(schema, doc)
    assert result["redacted"] == {
        "users": [{"email": "***", "tags": ["***"]},
                  {"email": "***", "tags": []}]}
    assert doc["users"][0]["email"] == "a@b.c"


def test_pattern_and_additional_properties():
    schema = {
        "patternProperties": {"^secret_": {"x-sensitive": True}},
        "additionalProperties": {"properties": {"v": {"x-sensitive": True}}},
    }
    doc = {"secret_a": 1, "other": {"v": 2, "keep": 3}}
    result = redacted(schema, doc)
    assert result["redacted"] == {
        "secret_a": "***", "other": {"v": "***", "keep": 3}}


def test_additional_properties_false_does_not_redact():
    schema = {
        "properties": {"a": {"x-sensitive": True}},
        "additionalProperties": False,
    }
    result = redacted(schema, {"a": 1, "b": 2})
    assert result["redacted"] == {"a": "***", "b": 2}


def test_prefix_items_and_items_2020():
    schema = {"prefixItems": [{"x-sensitive": True}, {"type": "string"}],
              "items": {"x-sensitive": True}}
    result = redacted(schema, [1, "a", 3, 4])
    assert result["redacted"] == ["***", "a", "***", "***"]
    ptrs = [(r["instance_pointer"], r["schema_pointer"])
            for r in result["replacements"]]
    assert ("#/0", "#/prefixItems/0") in ptrs
    assert ("#/2", "#/items") in ptrs


def test_legacy_tuple_items_with_additional_items():
    schema = {"items": [{"x-sensitive": True}, {}],
              "additionalItems": {"x-sensitive": True}}
    result = redacted(schema, [1, 2, 3])
    assert result["redacted"] == ["***", 2, "***"]


def test_scalar_and_null_documents_pass_through():
    schema = {"type": "string"}
    out = redact.redact_documents(schema, [None, True, 42, "s", [1]])
    assert [r["redacted"] for r in out["results"]] == [
        None, True, 42, "s", [1]]


def test_root_sensitive_masks_whole_document():
    result = redacted({"x-sensitive": True, "type": "object"}, {"a": {"b": 1}})
    assert result["redacted"] == "***"
    assert [r["instance_pointer"] for r in result["replacements"]] == ["#"]


def test_sensitive_ancestor_short_circuits_descendants():
    schema = {"properties": {"wrap": {
        "x-sensitive": True,
        "properties": {"inner": {"x-sensitive": True}}}}}
    result = redacted(schema, {"wrap": {"inner": 1}})
    assert result["redacted"] == {"wrap": "***"}
    # 祖先命中后不再下钻：同一位置只一条记录
    assert [r["instance_pointer"] for r in result["replacements"]] == ["#/wrap"]


def test_pointer_escaping_for_special_keys():
    schema = {"properties": {"a/b": {"x-sensitive": True},
                             "m~n": {"x-sensitive": True}}}
    result = redacted(schema, {"a/b": 1, "m~n": 2})
    ptrs = {r["instance_pointer"] for r in result["replacements"]}
    assert ptrs == {"#/a~1b", "#/m~0n"}
    assert result["redacted"] == {"a/b": "***", "m~n": "***"}


def test_results_preserve_input_order_and_indices():
    schema = {"properties": {"s": {"x-sensitive": True}}}
    out = redact.redact_documents(schema, [{"s": 1}, {"s": 2}, {"x": 3}])
    assert [r["index"] for r in out["results"]] == [0, 1, 2]
    assert out["results"][2]["redacted"] == {"x": 3}


# ---------------------------------------------------------------------------
# $ref
# ---------------------------------------------------------------------------


def test_local_ref_resolved():
    schema = {
        "properties": {"phone": {"$ref": "#/$defs/Phone"}},
        "$defs": {"Phone": {"type": "string", "x-sensitive": True}},
    }
    result = redacted(schema, {"phone": "123"})
    assert result["redacted"] == {"phone": "***"}
    assert result["replacements"][0]["schema_pointer"] == "#/$defs/Phone"


def test_ref_root_pointer():
    schema = {
        "type": "object",
        "x-sensitive": False,
        "properties": {"self": {"$ref": "#"}},
    }
    # 根节点不敏感，自指展开到同一实例位置时不应无限递归
    result = redacted(schema, {"self": {"self": {}}})
    assert result["redacted"] == {"self": {"self": {}}}


def test_recursive_linked_list_terminates_and_redacts_each_level():
    schema = {
        "type": "object",
        "properties": {
            "value": {"x-sensitive": True},
            "next": {"$ref": "#/$defs/Node"},
        },
        "$defs": {"Node": {
            "type": "object",
            "properties": {
                "value": {"x-sensitive": True},
                "next": {"$ref": "#/$defs/Node"},
            },
        }},
    }
    doc = {"value": 1, "next": {"value": 2, "next": {"value": 3}}}
    result = redacted(schema, doc)
    assert result["redacted"] == {
        "value": "***",
        "next": {"value": "***", "next": {"value": "***"}},
    }
    assert doc["next"]["value"] == 2


def test_unresolvable_ref_raises_with_schema_pointer():
    schema = {"properties": {"x": {"$ref": "#/$defs/Missing"}}}
    with pytest.raises(redact.UnresolvableReference) as exc:
        redact.redact_documents(schema, [{"x": 1}])
    assert exc.value.schema_pointer == "#/properties/x"
    assert exc.value.reason == "target_not_found"
    assert exc.value.instance_pointer == "#/x"


def test_external_ref_rejected():
    schema = {"properties": {"x": {"$ref": "https://e.com/s.json#/a"}}}
    with pytest.raises(redact.UnresolvableReference) as exc:
        redact.redact_documents(schema, [{"x": 1}])
    assert exc.value.reason == "external_reference"
    assert exc.value.schema_pointer == "#/properties/x"


def test_name_fragment_ref_rejected():
    schema = {"properties": {"x": {"$ref": "#anchor"}}}
    with pytest.raises(redact.UnresolvableReference) as exc:
        redact.redact_documents(schema, [{"x": 1}])
    assert exc.value.reason == "name_fragment_unsupported"


# ---------------------------------------------------------------------------
# 组合关键字
# ---------------------------------------------------------------------------


def test_allof_every_branch_traversed():
    schema = {
        "type": "object",
        "allOf": [
            {"properties": {"a": {"x-sensitive": True}}},
            {"properties": {"b": {"x-sensitive": True}}},
        ],
    }
    result = redacted(schema, {"a": 1, "b": 2, "c": 3})
    assert result["redacted"] == {"a": "***", "b": "***", "c": 3}


def test_oneof_only_passing_branch_traversed():
    schema = {
        "oneOf": [
            {"type": "object",
             "properties": {"t": {"const": "a"}, "secret": {"x-sensitive": True}},
             "required": ["t"]},
            {"type": "object",
             "properties": {"t": {"const": "b"}, "secret": {"x-sensitive": True}},
             "required": ["t"]},
        ],
    }
    out = redact.redact_documents(schema, [
        {"t": "a", "secret": "shh"},
        {"t": "b", "secret": "boo"},
    ])
    assert out["results"][0]["redacted"] == {"t": "a", "secret": "***"}
    assert (out["results"][0]["replacements"][0]["schema_pointer"]
            == "#/oneOf/0/properties/secret")
    assert out["results"][1]["redacted"] == {"t": "b", "secret": "***"}
    assert (out["results"][1]["replacements"][0]["schema_pointer"]
            == "#/oneOf/1/properties/secret")


def test_anyof_only_passing_branch_traversed():
    schema = {"anyOf": [
        {"type": "string", "x-sensitive": True},
        {"type": "integer"},
    ]}
    out = redact.redact_documents(schema, [7, "hi"])
    assert out["results"][0]["redacted"] == 7
    assert out["results"][0]["replacements"] == []
    assert out["results"][1]["redacted"] == "***"


def test_anyof_multiple_passing_branches_all_traversed():
    schema = {
        "type": "object",
        "anyOf": [
            {"properties": {"a": {"x-sensitive": True}}},
            {"properties": {"b": {"x-sensitive": True}}},
        ],
    }
    # 空约束分支都校验通过：a 与 b 都应脱敏
    result = redacted(schema, {"a": 1, "b": 2})
    assert result["redacted"] == {"a": "***", "b": "***"}


def test_branch_validation_uses_original_value_not_mask():
    """分支判定必须基于原值：先在分支内把判别字段标记敏感也不能误路由。"""
    schema = {
        "type": "object",
        "oneOf": [
            {"properties": {"kind": {"const": "a", "x-sensitive": True},
                            "a_secret": {"x-sensitive": True}}},
            {"properties": {"kind": {"const": "b"},
                            "b_secret": {"x-sensitive": True}}},
        ],
    }
    result = redacted(schema, {"kind": "a", "a_secret": "shh", "b_secret": "x"})
    # 即使 kind 自身会被掩码，分支判定仍按原值 "a" 路由
    assert result["redacted"] == {"kind": "***", "a_secret": "***", "b_secret": "x"}


def test_allof_and_properties_duplicate_hit_deduped():
    schema = {
        "type": "object",
        "properties": {"a": {"x-sensitive": True}},
        "allOf": [{"properties": {"a": {"x-sensitive": True}}}],
    }
    result = redacted(schema, {"a": 1})
    assert result["redacted"] == {"a": "***"}
    assert len(result["replacements"]) == 1


def test_recursive_ref_inside_allof_terminates():
    schema = {
        "type": "object",
        "properties": {
            "value": {"x-sensitive": True},
            "child": {"allOf": [{"$ref": "#"}]},
        },
    }
    doc = {"value": 1, "child": {"value": 2, "child": {"value": 3}}}
    result = redacted(schema, doc)
    assert result["redacted"] == {
        "value": "***",
        "child": {"value": "***", "child": {"value": "***"}},
    }


# ---------------------------------------------------------------------------
# 顺序与不修改入参
# ---------------------------------------------------------------------------


def test_replacements_sorted_by_instance_pointer():
    schema = {
        "properties": {
            "z": {"x-sensitive": True},
            "arr": {"type": "array", "items": {"x-sensitive": True}},
            "a": {"x-sensitive": True},
        },
    }
    result = redacted(schema, {"z": 1, "arr": [9, 8], "a": 1})
    assert [r["instance_pointer"] for r in result["replacements"]] == [
        "#/a", "#/arr/0", "#/arr/1", "#/z"]


def test_schema_not_mutated():
    schema = {"properties": {"a": {"$ref": "#/$defs/S"}},
              "$defs": {"S": {"x-sensitive": True}}}
    import copy
    snapshot = copy.deepcopy(schema)
    redact.redact_documents(schema, [{"a": 1}, {"a": 2}])
    assert schema == snapshot


# ---------------------------------------------------------------------------
# 现代方言下 $ref 同级子规则（Draft 2019-09 / 2020-12 / 形态判定）
# ---------------------------------------------------------------------------


def test_modern_ref_sibling_properties_redacted_2020_12():
    schema = {
        "$schema": DRAFT_2020_12,
        "type": "object",
        "properties": {
            "o": {"$ref": "#/$defs/Base",
                  "properties": {"extra": {"x-sensitive": True}}},
        },
        "$defs": {"Base": {"type": "object",
                           "properties": {"id": {"x-sensitive": True}}}},
    }
    result = redacted(schema, {"o": {"id": "x", "extra": "y"}})
    assert result["redacted"] == {"o": {"id": "***", "extra": "***"}}
    ptrs = {r["instance_pointer"]: r["schema_pointer"]
            for r in result["replacements"]}
    # 命中值返回其实际 schema 指针：目标内与同级各指各的位置
    assert ptrs["#/o/id"] == "#/$defs/Base/properties/id"
    assert ptrs["#/o/extra"] == "#/properties/o/properties/extra"


def test_modern_ref_sibling_properties_redacted_2019_09():
    schema = {
        "$schema": DRAFT_2019_09,
        "properties": {
            "o": {"$ref": "#/$defs/Base",
                  "properties": {"extra": {"x-sensitive": True}}},
        },
        "$defs": {"Base": {"properties": {"id": {"x-sensitive": True}}}},
    }
    result = redacted(schema, {"o": {"id": 1, "extra": 2}})
    assert result["redacted"] == {"o": {"id": "***", "extra": "***"}}


def test_dialect_inferred_modern_when_no_schema_keyword():
    # 未声明 $schema：按 jsonschema 默认方言（2020-12）走现代语义
    schema = {
        "properties": {
            "o": {"$ref": "#/$defs/Base",
                  "properties": {"extra": {"x-sensitive": True}}},
        },
        "$defs": {"Base": {"properties": {"id": {"x-sensitive": True}}}},
    }
    result = redacted(schema, {"o": {"id": 1, "extra": 2}})
    assert result["redacted"] == {"o": {"id": "***", "extra": "***"}}


def test_modern_ref_sibling_array_items_redacted():
    schema = {
        "$schema": DRAFT_2020_12,
        "properties": {"arr": {
            "$ref": "#/$defs/Arr",
            "prefixItems": [{"x-sensitive": True}, {}],
            "items": {"x-sensitive": True},
        }},
        "$defs": {"Arr": {"type": "array"}},
    }
    result = redacted(schema, {"arr": [1, 2, 3]})
    assert result["redacted"] == {"arr": ["***", 2, "***"]}
    ptrs = {(r["instance_pointer"], r["schema_pointer"])
            for r in result["replacements"]}
    assert ("#/arr/0", "#/properties/arr/prefixItems/0") in ptrs
    assert ("#/arr/2", "#/properties/arr/items") in ptrs


def test_modern_ref_sibling_homogeneous_items_redacted():
    schema = {
        "$schema": DRAFT_2020_12,
        "properties": {"arr": {"$ref": "#/$defs/Arr",
                               "items": {"x-sensitive": True}}},
        "$defs": {"Arr": {"type": "array", "items": {"type": "integer"}}},
    }
    result = redacted(schema, {"arr": [1, 2, 3]})
    assert result["redacted"] == {"arr": ["***", "***", "***"]}


def test_modern_ref_sibling_pattern_and_additional_properties():
    schema = {
        "$schema": DRAFT_2020_12,
        "properties": {"o": {
            "$ref": "#/$defs/O",
            "patternProperties": {"^x_": {"x-sensitive": True}},
            "additionalProperties": {"properties": {"p": {"x-sensitive": True}}},
        }},
        "$defs": {"O": {"properties": {"name": {"x-sensitive": True}}}},
    }
    result = redacted(schema, {"o": {"name": "n", "x_1": 1,
                                     "other": {"p": 2}}})
    assert result["redacted"] == {
        "o": {"name": "***", "x_1": "***", "other": {"p": "***"}}}


def test_modern_ref_sibling_composition_branches_redacted():
    schema = {
        "$schema": DRAFT_2020_12,
        "properties": {"v": {
            "$ref": "#/$defs/B",
            "allOf": [{"properties": {"s": {"x-sensitive": True}}}],
        }},
        "$defs": {"B": {"properties": {"t": {"x-sensitive": True}}}},
    }
    result = redacted(schema, {"v": {"t": 1, "s": 2}})
    assert result["redacted"] == {"v": {"t": "***", "s": "***"}}
    ptrs = {r["instance_pointer"]: r["schema_pointer"]
            for r in result["replacements"]}
    assert ptrs["#/v/s"] == "#/properties/v/allOf/0/properties/s"
    assert ptrs["#/v/t"] == "#/$defs/B/properties/t"


def test_modern_ref_sibling_oneof_routes_on_original_value():
    schema = {
        "$schema": DRAFT_2020_12,
        "properties": {"r": {
            "$ref": "#/$defs/R",
            "oneOf": [
                {"properties": {"kind": {"const": "a"},
                                "sec_a": {"x-sensitive": True}}},
                {"properties": {"kind": {"const": "b"},
                                "sec_b": {"x-sensitive": True}}},
            ]}},
        "$defs": {"R": {"properties": {"shared": {"x-sensitive": True}}}},
    }
    doc = {"r": {"kind": "a", "shared": 1, "sec_a": 2, "sec_b": 3}}
    result = redacted(schema, doc)
    assert result["redacted"] == {
        "r": {"kind": "a", "shared": "***", "sec_a": "***", "sec_b": 3}}


# ---------------------------------------------------------------------------
# Draft-07 及更早：$ref 同级子规则仍被忽略
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("dialect", [DRAFT_4, DRAFT_6, DRAFT_7])
def test_legacy_dialects_ignore_ref_siblings(dialect):
    schema = {
        "$schema": dialect,
        "type": "object",
        "properties": {
            "o": {"$ref": "#/definitions/Base",
                  "properties": {"extra": {"x-sensitive": True}}},
        },
        "definitions": {"Base": {"type": "object",
                                 "properties": {"id": {"x-sensitive": True}}}},
    }
    result = redacted(schema, {"o": {"id": 1, "extra": 2}})
    # 引用目标内命中照常脱敏；同级 extra 在旧方言下被忽略
    assert result["redacted"] == {"o": {"id": "***", "extra": 2}}
    ptrs = {r["instance_pointer"] for r in result["replacements"]}
    assert ptrs == {"#/o/id"}


def test_legacy_tuple_items_shape_infers_legacy_dialect():
    # 无 $schema 但出现 draft-04/06/07 元组写法 items: [...]，
    # 按现有形态判定为旧方言：$ref 同级 properties 不参与遍历
    schema = {
        "type": "object",
        "properties": {
            "o": {"$ref": "#/$defs/Base",
                  "properties": {"extra": {"x-sensitive": True}}},
            "legacy": {"items": [{}]},  # 旧方言形态标志
        },
        "$defs": {"Base": {"properties": {"id": {"x-sensitive": True}}}},
    }
    result = redacted(schema, {"o": {"id": 1, "extra": 2}})
    assert result["redacted"] == {"o": {"id": "***", "extra": 2}}


# ---------------------------------------------------------------------------
# 嵌套 / 循环引用：同一实例位置只展开一次，但不漏同级子规则
# ---------------------------------------------------------------------------


def test_modern_cycle_skips_duplicate_ref_but_still_walks_siblings():
    # Node -> Node2 -> Node（同实例位置成环）；Node 上有同级敏感属性 tag。
    # 第二次回到 Node 时引用目标被跳过，但 tag 仍须脱敏。
    schema = {
        "$schema": DRAFT_2020_12,
        "type": "object",
        "properties": {"o": {"$ref": "#/$defs/Node"}},
        "$defs": {
            "Node": {"$ref": "#/$defs/Node2",
                     "properties": {"tag": {"x-sensitive": True}}},
            "Node2": {"$ref": "#/$defs/Node"},
        },
    }
    result = redacted(schema, {"o": {"tag": "secret"}})
    assert result["redacted"] == {"o": {"tag": "***"}}
    assert result["replacements"][0]["schema_pointer"] == \
        "#/$defs/Node/properties/tag"


def test_legacy_cycle_ignores_siblings_of_skipped_ref():
    schema = {
        "$schema": DRAFT_7,
        "type": "object",
        "properties": {"o": {"$ref": "#/definitions/Node"}},
        "definitions": {
            "Node": {"$ref": "#/definitions/Node2",
                     "properties": {"tag": {"x-sensitive": True}}},
            "Node2": {"$ref": "#/definitions/Node"},
        },
    }
    result = redacted(schema, {"o": {"tag": "secret"}})
    assert result["redacted"] == {"o": {"tag": "secret"}}
    assert result["replacements"] == []


def test_modern_root_self_ref_siblings_at_each_instance_position():
    schema = {
        "$schema": DRAFT_2020_12,
        "type": "object",
        "properties": {
            "head": {"x-sensitive": True},
            "next": {"$ref": "#",
                     "properties": {"extra": {"x-sensitive": True}}},
        },
    }
    doc = {"head": 1, "next": {"head": 2, "extra": 9,
                                "next": {"extra": 7}}}
    result = redacted(schema, doc)
    assert result["redacted"] == {
        "head": "***",
        "next": {"head": "***", "extra": "***",
                 "next": {"extra": "***"}},
    }


def test_duplicate_ref_via_sibling_branch_keeps_branch_siblings():
    # 节点先 $ref 到 B，又在同级 allOf 分支里重复 $ref 到 B；
    # 分支内第二次展开 B 被跳过，但分支节点自身的同级敏感字段仍须脱敏。
    schema = {
        "$schema": DRAFT_2020_12,
        "properties": {"o": {
            "$ref": "#/$defs/B",
            "allOf": [{"$ref": "#/$defs/B",
                       "properties": {"only_sibling": {
                           "x-sensitive": True}}}],
        }},
        "$defs": {"B": {"properties": {"from_target": {
            "x-sensitive": True}}}},
    }
    result = redacted(schema, {"o": {"from_target": 1, "only_sibling": 2}})
    assert result["redacted"] == {
        "o": {"from_target": "***", "only_sibling": "***"}}
    ptrs = {r["instance_pointer"]: r["schema_pointer"]
            for r in result["replacements"]}
    assert ptrs["#/o/only_sibling"] == \
        "#/properties/o/allOf/0/properties/only_sibling"
    assert ptrs["#/o/from_target"] == "#/$defs/B/properties/from_target"


def test_modern_recursive_linked_list_still_redacts_each_level():
    schema = {
        "$schema": DRAFT_2020_12,
        "type": "object",
        "properties": {
            "value": {"x-sensitive": True},
            "next": {"$ref": "#/$defs/Node"},
        },
        "$defs": {"Node": {
            "type": "object",
            "properties": {
                "value": {"x-sensitive": True},
                "next": {"$ref": "#/$defs/Node"},
            }}},
    }
    doc = {"value": 1, "next": {"value": 2, "next": {"value": 3}}}
    result = redacted(schema, doc)
    assert result["redacted"] == {
        "value": "***",
        "next": {"value": "***", "next": {"value": "***"}},
    }
