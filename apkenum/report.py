class ReportSection:
    def __init__(self, name):
        self.name = name
        self.values = []
        self.sub_sections = []

    def add_value(self, value):
        self.values.append(value)

    def add_all_values(self, values):
        self.values += values

    def add_sub_section(self, sub_section):
        self.sub_sections.append(sub_section)

class Report:
    def __init__(self):
        self.sections = []

    def add_section(self, section):
        self.sections.append(section)

class ReportFormatter:
    def __init__(self):
        pass

    def write_report(self, report, output_stream):
        raise NotImplementedError

class TextReportFormatter(ReportFormatter):
    def __init__(self):
        super()

    def write_report(self, report, output_stream):
        for section in report.sections:
            output_stream.write("* " + section.name + "\n")
            self._write_section(1, section, output_stream)

    def _write_section(self, level, section, output_stream):
        prefix = "\t"*level
        for value in section.values:
            output_stream.write(prefix + "- " + value + "\n")
        for sub_section in section.sub_sections:
            output_stream.write(prefix + "* " + sub_section.name)
            self._write_section(level + 1, sub_section, output_stream)

