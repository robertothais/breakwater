from pathlib import Path

import requests
import typer
from lxml import etree
from sqlalchemy import ForeignKey, Integer, String, Text, create_engine
from sqlalchemy.orm import (
    Mapped,
    declarative_base,
    mapped_column,
    relationship,
    sessionmaker,
)

app = typer.Typer(help="Manage the catalog of Korean banking software.")

ENGINE = create_engine("sqlite:///:memory:")
Base = declarative_base()


class Service(Base):
    __tablename__ = "services"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    display_name: Mapped[str | None] = mapped_column(String)
    category: Mapped[str | None] = mapped_column(String)
    url: Mapped[str | None] = mapped_column(String)
    compatibility_notes: Mapped[str | None] = mapped_column(Text)

    packages: Mapped[list["ServicePackageUrl"]] = relationship(back_populates="service")


class Package(Base):
    __tablename__ = "packages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String, unique=True)

    services: Mapped[list["ServicePackageUrl"]] = relationship(back_populates="package")


class ServicePackageUrl(Base):
    __tablename__ = "service_package_urls"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    service_id: Mapped[str] = mapped_column(ForeignKey("services.id"))
    package_id: Mapped[int] = mapped_column(ForeignKey("packages.id"))
    url: Mapped[str | None] = mapped_column(String)
    arguments: Mapped[str | None] = mapped_column(String)
    package: Mapped["Package"] = relationship(back_populates="services")
    service: Mapped["Service"] = relationship(back_populates="packages")


class IESite(Base):
    __tablename__ = "ie_sites"

    url: Mapped[str] = mapped_column(String, primary_key=True)


@app.command()
def update():
    """Update the catalog from the TableClothCatalog repository."""
    DB_PATH.parent.mkdir(exist_ok=True)
    Base.metadata.create_all(ENGINE)

    session_local = sessionmaker(bind=ENGINE)
    session = session_local()

    # Fetch Catalog.xml
    typer.echo("Fetching Catalog.xml...")
    catalog_xml_url = "https://raw.githubusercontent.com/yourtablecloth/TableClothCatalog/main/docs/Catalog.xml"
    try:
        response = requests.get(catalog_xml_url)
        response.raise_for_status()
        catalog_xml_content = response.text
        with open(DB_PATH.parent / "Catalog.xml", "w", encoding="utf-8") as f:
            f.write(catalog_xml_content)
    except requests.exceptions.RequestException as e:
        typer.echo(f"Failed to fetch Catalog.xml: {e}", err=True)
        raise typer.Exit(1) from e

    # Fetch sites.xml
    typer.echo("Fetching sites.xml...")
    sites_xml_url = "https://raw.githubusercontent.com/yourtablecloth/TableClothCatalog/main/docs/sites.xml"
    try:
        response = requests.get(sites_xml_url)
        response.raise_for_status()
        sites_xml_content = response.text
        with open(DB_PATH.parent / "sites.xml", "w", encoding="utf-8") as f:
            f.write(sites_xml_content)
    except requests.exceptions.RequestException as e:
        typer.echo(f"Failed to fetch sites.xml: {e}", err=True)
        raise typer.Exit(1) from e

    # Parse and update database
    typer.echo("Parsing and updating database...")

    with session.begin():
        # Clear existing data
        session.query(ServicePackageUrl).delete()
        session.query(Service).delete()
        session.query(Package).delete()
        session.query(IESite).delete()

        # Parse Catalog.xml
        root = etree.fromstring(catalog_xml_content.encode("utf-8"))
        for service_element in root.findall(".//Service"):
            service = Service(
                id=service_element.get("Id"),
                display_name=service_element.get("DisplayName"),
                category=service_element.get("Category"),
                url=service_element.get("Url"),
                compatibility_notes=service_element.findtext("en-US-CompatNotes"),
            )
            session.add(service)

            for package_element in service_element.findall(".//Package"):
                package_name = package_element.get("Name")
                package = session.query(Package).filter_by(name=package_name).first()
                if not package:
                    package = Package(name=package_name)
                    session.add(package)

                association = ServicePackageUrl(
                    url=package_element.get("Url"),
                    arguments=package_element.get("Arguments"),
                )
                association.package = package
                service.packages.append(association)

        # Parse sites.xml
        root = etree.fromstring(sites_xml_content.encode("utf-8"))
        for site_element in root.findall(".//site"):
            ie_site = IESite(url=site_element.get("url"))
            session.add(ie_site)

    session.close()

    typer.echo("Catalog database updated.")
