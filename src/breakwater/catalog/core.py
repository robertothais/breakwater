"""Core database models and session management for the catalog system."""

import xml.etree.ElementTree as ET
from contextlib import contextmanager

import requests
import typer
from sqlalchemy import ForeignKey, Integer, String, Text, create_engine
from sqlalchemy.orm import (
    Mapped,
    declarative_base,
    mapped_column,
    relationship,
    sessionmaker,
)

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


def _fetch_catalog_files():
    """Fetch catalog and sites XML files from GitHub."""
    # Fetch Catalog.xml
    catalog_xml_url = "https://raw.githubusercontent.com/yourtablecloth/TableClothCatalog/main/docs/Catalog.xml"
    try:
        response = requests.get(catalog_xml_url)
        response.raise_for_status()
        catalog_xml_content = response.text
    except requests.exceptions.RequestException as e:
        typer.echo(f"Failed to fetch Catalog.xml: {e}", err=True)
        raise typer.Exit(1) from e

    # Fetch sites.xml
    sites_xml_url = "https://raw.githubusercontent.com/yourtablecloth/TableClothCatalog/main/docs/sites.xml"
    try:
        response = requests.get(sites_xml_url)
        response.raise_for_status()
        sites_xml_content = response.text
    except requests.exceptions.RequestException as e:
        typer.echo(f"Failed to fetch sites.xml: {e}", err=True)
        raise typer.Exit(1) from e

    return catalog_xml_content, sites_xml_content


@contextmanager
def catalog_session():
    """Context manager that ensures database is populated and provides a session."""
    Base.metadata.create_all(ENGINE)
    session_local = sessionmaker(bind=ENGINE)

    # Check if already populated
    with session_local() as check_session:
        needs_population = check_session.query(Service).count() == 0

    if needs_population:
        # Fetch XML files
        catalog_xml_content, sites_xml_content = _fetch_catalog_files()

        # Populate database
        with session_local() as populate_session:
            # Parse Catalog.xml
            root = ET.fromstring(catalog_xml_content)
            for service_element in root.findall(".//Service"):
                service = Service(
                    id=service_element.get("Id"),
                    display_name=service_element.get("DisplayName"),
                    category=service_element.get("Category"),
                    url=service_element.get("Url"),
                    compatibility_notes=service_element.findtext("en-US-CompatNotes"),
                )
                populate_session.add(service)

                for package_element in service_element.findall(".//Package"):
                    package_name = package_element.get("Name")
                    package = (
                        populate_session.query(Package)
                        .filter_by(name=package_name)
                        .first()
                    )
                    if not package:
                        package = Package(name=package_name)
                        populate_session.add(package)
                        populate_session.flush()  # Ensure package gets an ID

                    association = ServicePackageUrl(
                        service_id=service.id,
                        package_id=package.id,
                        url=package_element.get("Url"),
                        arguments=package_element.get("Arguments"),
                    )
                    populate_session.add(association)

            # Parse sites.xml
            sites_root = ET.fromstring(sites_xml_content)
            for site_element in sites_root.findall(".//site"):
                ie_site = IESite(url=site_element.get("url"))
                populate_session.add(ie_site)

            populate_session.commit()

    # Provide a session for the caller
    session = session_local()
    try:
        yield session
    finally:
        session.close()
