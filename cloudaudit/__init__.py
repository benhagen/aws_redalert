import json


class BaseCheck:
    default_score = 0

    def __init__(self, notes=None):
        self.notes = notes

    @classmethod
    def from_notes(cls, notes):
        return cls(notes=notes)

    def __nonzero__(self):
        return bool(self.notes)

    def __str__(self):
        return "<Item Issue ID: {id}\n\tText: {text}\n\tDefault Score: {default_score}\n\tNotes: {notes}>".format(
            id=self.id, text=self.text, default_score=self.default_score, notes=json.dumps(self.notes))

    def __repr__(self):
        return self.__str__()