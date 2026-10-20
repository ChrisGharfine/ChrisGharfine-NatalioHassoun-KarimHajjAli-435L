"""Strict v1 audit/notification delivery receipts; malformed success stays pending."""


def valid_receipt(body, status, event_id, resource, id_field):
    if status not in (200, 201) or not isinstance(body, dict) or body.get("status") != "success":
        return False
    data = body.get("data")
    if (not isinstance(data, dict) or data.get("event_id") != str(event_id)
            or type(data.get("duplicate")) is not bool
            or data["duplicate"] != (status == 200) or resource not in data):
        return False
    record = data[resource]
    if record is None:
        return data["duplicate"]
    return (isinstance(record, dict) and type(record.get(id_field)) is int
            and record[id_field] > 0)
