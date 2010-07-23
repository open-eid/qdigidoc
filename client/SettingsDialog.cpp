/*
 * QDigiDocClient
 *
 * Copyright (C) 2009 Jargo Kõster <jargo@innovaatik.ee>
 * Copyright (C) 2009 Raul Metsma <raul@innovaatik.ee>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include "SettingsDialog.h"

#include "DigiDoc.h"
#include "version.h"

#include <common/CertificateWidget.h>
#include <common/Settings.h>
#include <common/SslCertificate.h>

#include <QDesktopServices>
#include <QFileDialog>

SettingsDialog::SettingsDialog( QWidget *parent )
:	QDialog( parent )
{
	setupUi( this );

	Settings s;
	s.beginGroup( "Client" );

	defaultSameDir->setChecked( s.value( "DefaultDir" ).isNull() );
	defaultDir->setText( s.value( "DefaultDir" ).toString() );
	showIntro->setChecked( s.value( "Intro", true ).toBool() );
	askSaveAs->setChecked( s.value( "AskSaveAs", false ).toBool() );

	const QString type = s.value( "type", "ddoc" ).toString();
	typeBDoc->setChecked( type == "bdoc" );
	typeDDoc->setChecked( type == "ddoc" );

	signRoleInput->setText( s.value( "Role" ).toString() );
	signResolutionInput->setText( s.value( "Resolution" ).toString() );
	signCityInput->setText( s.value( "City" ).toString() );
	signStateInput->setText( s.value( "State" ).toString() );
	signCountryInput->setText( s.value( "Country" ).toString() );
	signZipInput->setText( s.value( "Zip" ).toString() );

	signOverwrite->setChecked( s.value( "Overwrite", false ).toBool() );

	proxyHost->setText( DigiDoc::getConfValue( DigiDoc::ProxyHost ) );
	proxyPort->setText( DigiDoc::getConfValue( DigiDoc::ProxyPort ) );
	proxyUser->setText( DigiDoc::getConfValue( DigiDoc::ProxyUser ) );
	proxyPass->setText( DigiDoc::getConfValue( DigiDoc::ProxyPass ) );
	p12Cert->setText( DigiDoc::getConfValue( DigiDoc::PKCS12Cert ) );
	p12Pass->setText( DigiDoc::getConfValue( DigiDoc::PKCS12Pass ) );

	s.endGroup();
}

void SettingsDialog::on_p12Button_clicked()
{
	QString cert = DigiDoc::getConfValue( DigiDoc::PKCS12Cert );
	if( cert.isEmpty() )
		cert = QDesktopServices::storageLocation( QDesktopServices::DocumentsLocation );
	else
		cert = QFileInfo( cert ).path();
	cert = QFileDialog::getOpenFileName( this, tr("Select PKCS#12 certificate"), cert,
		tr("PKCS#12 Certificates (*.p12 *.p12d)") );
	if( !cert.isEmpty() )
		setP12Cert( cert );
}

void SettingsDialog::on_p12Cert_textChanged( const QString &text )
{ showP12Cert->setEnabled( QFile::exists( text ) ); }

void SettingsDialog::on_selectDefaultDir_clicked()
{
	QString dir = Settings().value( "Client/DefaultDir" ).toString();
	if( dir.isEmpty() )
		dir = QDesktopServices::storageLocation( QDesktopServices::DocumentsLocation );
	dir = QFileDialog::getExistingDirectory( this, tr("Select folder"), dir );
	if( !dir.isEmpty() )
	{
		Settings().setValue( "Client/DefaultDir", dir );
		defaultDir->setText( dir );
	}
	defaultSameDir->setChecked( defaultDir->text().isEmpty() );
}

void SettingsDialog::on_showP12Cert_clicked()
{
	QFile f( p12Cert->text() );
	if( !f.open( QIODevice::ReadOnly ) )
		return;

	PKCS12Certificate cert( &f, p12Pass->text().toLatin1() );
	f.close();
	if( cert.certificate().isNull() )
		return;
	CertificateDialog d( cert.certificate() );
	d.exec();
}

void SettingsDialog::save()
{
	Settings s;
	s.beginGroup( "Client" );
	s.setValue( "Intro", showIntro->isChecked() );
	s.setValue( "Overwrite", signOverwrite->isChecked() );
	s.setValue( "AskSaveAs", askSaveAs->isChecked() );
	s.setValue( "type", typeBDoc->isChecked() ? "bdoc" : "ddoc" );
	if( defaultSameDir->isChecked() )
	{
		defaultDir->clear();
		s.remove( "DefaultDir" );
	}

	DigiDoc::setConfValue( DigiDoc::ProxyHost, proxyHost->text() );
	DigiDoc::setConfValue( DigiDoc::ProxyPort, proxyPort->text() );
	DigiDoc::setConfValue( DigiDoc::ProxyUser, proxyUser->text() );
	DigiDoc::setConfValue( DigiDoc::ProxyPass, proxyPass->text() );
	DigiDoc::setConfValue( DigiDoc::PKCS12Cert, p12Cert->text() );
	DigiDoc::setConfValue( DigiDoc::PKCS12Pass, p12Pass->text() );

	s.endGroup();

	saveSignatureInfo(
		signRoleInput->text(),
		signResolutionInput->text(),
		signCityInput->text(),
		signStateInput->text(),
		signCountryInput->text(),
		signZipInput->text(),
		true );
}

void SettingsDialog::saveSignatureInfo(
		const QString &role,
		const QString &resolution,
		const QString &city,
		const QString &state,
		const QString &country,
		const QString &zip,
		bool force )
{
	Settings s;
	s.beginGroup( "Client" );
	if( force || s.value( "Overwrite", "false" ).toBool() )
	{
		s.setValue( "Role", role );
		s.setValue( "Resolution", resolution );
		s.setValue( "City", city );
		s.setValue( "State", state ),
		s.setValue( "Country", country );
		s.setValue( "Zip", zip );
	}
	s.endGroup();
}

void SettingsDialog::setP12Cert( const QString &cert )
{
	DigiDoc::setConfValue( DigiDoc::PKCS12Cert, cert );
	p12Cert->setText( cert );
	tabWidget->setCurrentIndex( 1 );
}
