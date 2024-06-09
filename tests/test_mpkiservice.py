import unittest

from fastapi.testclient import TestClient
from mpkiservice.main import app


class TestAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def create_certificat(self, name):
        response = self.client.post(
            "/certs",
            json={
                "certificate": {
                    "name": name,
                },
                "partner": {
                    "name": "john",
                    "phone": "+33600000000",
                    "email": "john@example.org",
                },
                "location": {
                    "name": "Bureau",
                    "company": "Akretion",
                    "city": "Villeurbanne",
                    "zipcode": "69100",
                    "country": "France",
                },
            },
            auth=("bob", "incroyableeponge"),
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def test_create_certs(self):
        res = self.create_certificat("foo")
        self.assertEqual(res["name"], "foo")
        self.assertTrue(res["valid"])

    def test_revoke_certs(self):
        res = self.create_certificat("foo")
        serial = res["serial"]
        response = self.client.delete(
            f"/certs/{serial}", auth=("bob", "incroyableeponge")
        )
        self.assertEqual(response.status_code, 200)
        res = response.json()
        self.assertEqual(res["serial"], serial)
        self.assertFalse(res["valid"])
