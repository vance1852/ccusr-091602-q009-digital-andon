"""拓扑版本与依赖传播测试。"""
import unittest

from app.topology import Topology, downstream, impacted_units, upstream_chain


def _build():
    return Topology.from_dict({
        "versions": [
            {"version": "v1", "effective_from": 0, "devices": [
                {"id": "D", "unit": "u", "kind": "drive"},
                {"id": "C", "unit": "u", "kind": "conv", "depends_on": ["D"]},
                {"id": "V", "unit": "u", "kind": "vis", "depends_on": ["C"]},
            ]},
            {"version": "v2", "effective_from": 1000, "devices": [
                {"id": "D", "unit": "u", "kind": "drive"},
                {"id": "C", "unit": "u", "kind": "conv", "depends_on": ["D"]},
                {"id": "V", "unit": "u", "kind": "vis", "depends_on": ["C"]},
                {"id": "V2", "unit": "u", "kind": "vis", "depends_on": ["C"]},
            ]},
        ]
    })


class TopologyTest(unittest.TestCase):
    def test_version_selection_by_timestamp(self):
        topo = _build()
        self.assertEqual(topo.version_at(999).version, "v1")
        self.assertEqual(topo.version_at(1000).version, "v2")
        self.assertEqual(topo.version_at(5000).version, "v2")
        self.assertNotIn("V2", topo.version_at(500).devices)
        self.assertIn("V2", topo.version_at(1000).devices)

    def test_downstream_transitive_closure(self):
        topo = _build()
        self.assertEqual(downstream(topo.version_at(0), "D"), ("D", "C", "V"))
        self.assertEqual(downstream(topo.version_at(1000), "C"),
                         ("C", "V", "V2"))

    def test_upstream_chain(self):
        topo = _build()
        self.assertEqual(upstream_chain(topo.current(), "V"), ("V", "C", "D"))

    def test_impacted_units(self):
        topo = _build()
        self.assertEqual(impacted_units(topo.current(), ["D", "V"]), ("u",))

    def test_unknown_dependency_rejected(self):
        with self.assertRaises(ValueError):
            Topology.from_dict({"versions": [
                {"version": "v1", "effective_from": 0, "devices": [
                    {"id": "C", "unit": "u", "depends_on": ["GHOST"]}]}]})


if __name__ == "__main__":
    unittest.main()
