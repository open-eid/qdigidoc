/*
 * QDigiDocClient
 *
 * Copyright (C) 2009-2013 Jargo Kõster <jargo@innovaatik.ee>
 * Copyright (C) 2009-2013 Raul Metsma <raul@innovaatik.ee>
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
#include "ui_SettingsDialog.h"

#include "AccessCert.h"
#include "Application.h"
#include "RegisterP12.h"
#include "QSigner.h"

#include <common/CertificateWidget.h>
#include <common/FileDialog.h>
#include <common/Settings.h>
#include <common/SslCertificate.h>
#include <common/TokenData.h>

#include <QtCore/QDateTime>
#include <QtCore/QUrl>
#include <QtGui/QDropEvent>
#if QT_VERSION >= 0x050000
#include <QtWidgets/QMessageBox>
#else
#include <QtGui/QMessageBox>
#endif

#if QT_VERSION < 0x050000
Q_DECLARE_METATYPE(QSslCertificate)
#endif

SettingsDialog::SettingsDialog( QWidget *parent )
:	QDialog( parent )
,	d( new Ui::SettingsDialog )
{
	d->setupUi( this );
	setAttribute( Qt::WA_DeleteOnClose );
	Common::setAccessibleName( d->p12Label );

	Settings s;
	d->showIntro->setChecked( s.value( "Crypto/Intro", true ).toBool() );
	s.beginGroup( "Client" );
	d->showIntro->setChecked( s.value( "Intro", true ).toBool() );
	updateCert();
#ifdef Q_OS_MAC
	d->label->hide();
	d->defaultSameDir->hide();
	d->defaultDir->hide();
	d->selectDefaultDir->hide();
	d->askSaveAs->hide();
#else
	d->defaultSameDir->setChecked( s.value( "DefaultDir" ).isNull() );
	d->defaultDir->setText( s.value( "DefaultDir" ).toString() );
	d->askSaveAs->setChecked( s.value( "AskSaveAs", true ).toBool() );
#endif

	const QString type = s.value( "type", "ddoc" ).toString();
	d->typeBDoc->setChecked( type == "bdoc" );
	d->typeDDoc->setChecked( type == "ddoc" );

	d->signRoleInput->setText( s.value( "Role" ).toString() );
	d->signResolutionInput->setText( s.value( "Resolution" ).toString() );
	d->signCityInput->setText( s.value( "City" ).toString() );
	d->signStateInput->setText( s.value( "State" ).toString() );
	d->signCountryInput->setText( s.value( "Country" ).toString() );
	d->signZipInput->setText( s.value( "Zip" ).toString() );

	d->signOverwrite->setChecked( s.value( "Overwrite", false ).toBool() );

	d->proxyHost->setText( Application::confValue( Application::ProxyHost ).toString() );
	d->proxyPort->setText( Application::confValue( Application::ProxyPort ).toString() );
	d->proxyUser->setText( Application::confValue( Application::ProxyUser ).toString() );
	d->proxyPass->setText( Application::confValue( Application::ProxyPass ).toString() );
	d->p12Ignore->setChecked( Application::confValue( Application::PKCS12Disable, false ).toBool() );

	s.endGroup();
}

SettingsDialog::~SettingsDialog() { delete d; }

void SettingsDialog::on_p12Install_clicked()
{
	RegisterP12 *p12 = new RegisterP12( this );
	if( p12->exec() )
		updateCert();
}

void SettingsDialog::on_p12Remove_clicked()
{
	AccessCert().remove();
	updateCert();
}

void SettingsDialog::on_p12Update_clicked()
{
	AccessCert a( this );
	if( a.download( qApp->signer()->tokensign().card().isEmpty() ) )
		updateCert();
}

void SettingsDialog::on_selectDefaultDir_clicked()
{
#ifndef Q_OS_MAC
	QString dir = Settings().value( "Client/DefaultDir" ).toString();
	dir = FileDialog::getExistingDirectory( this, tr("Select folder"), dir );
	if( !dir.isEmpty() )
	{
		Settings().setValue( "Client/DefaultDir", dir );
		d->defaultDir->setText( dir );
	}
	d->defaultSameDir->setChecked( d->defaultDir->text().isEmpty() );
#endif
}

void SettingsDialog::on_showP12Cert_clicked()
{
	CertificateDialog(
		d->showP12Cert->property( "cert" ).value<QSslCertificate>() ).exec();
}

void SettingsDialog::on_typeBDoc_clicked( bool checked )
{
	if( !checked )
		return;

	QMessageBox b( QMessageBox::Information, windowTitle(), tr(
		"BDOC is new format for digital signatures, which may yet not be supported "
		"by all information systems and applications. Please note that the recipient "
		"might be not capable opening a document signed in this format. "
		"<a href=\"http://www.id.ee/eng/bdoc\">Additional information</a>."),
		QMessageBox::NoButton, this );
	if( QLabel *l = b.findChild<QLabel*>() )
	{
		l->setTextInteractionFlags( Qt::LinksAccessibleByKeyboard|Qt::LinksAccessibleByMouse );
		Common::setAccessibleName( l );
	}
	b.exec();
}

void SettingsDialog::save()
{
	Settings s;
	s.setValue( "Crypto/Intro", d->showIntro->isChecked() );
	s.beginGroup( "Client" );
	s.setValue( "Intro", d->showIntro->isChecked() );
	s.setValue( "Overwrite", d->signOverwrite->isChecked() );
#ifndef Q_OS_MAC
	s.setValue( "AskSaveAs", d->askSaveAs->isChecked() );
	if( d->defaultSameDir->isChecked() )
	{
		d->defaultDir->clear();
		s.remove( "DefaultDir" );
	}
#endif
	s.setValue( "type", d->typeBDoc->isChecked() ? "bdoc" : "ddoc" );

	Application::setConfValue( Application::ProxyHost, d->proxyHost->text() );
	Application::setConfValue( Application::ProxyPort, d->proxyPort->text() );
	Application::setConfValue( Application::ProxyUser, d->proxyUser->text() );
	Application::setConfValue( Application::ProxyPass, d->proxyPass->text() );
	Application::setConfValue( Application::PKCS12Disable, d->p12Ignore->isChecked() );

	saveSignatureInfo(
		d->signRoleInput->text(),
		d->signResolutionInput->text(),
		d->signCityInput->text(),
		d->signStateInput->text(),
		d->signCountryInput->text(),
		d->signZipInput->text(),
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

void SettingsDialog::setPage( int page ) { d->tabWidget->setCurrentIndex( page ); }

void SettingsDialog::updateCert()
{
	QSslCertificate c = AccessCert::cert();
	if( !c.isNull() )
		d->p12Error->setText( tr("Issued to: %1<br />Valid to: %2 %3")
			.arg( SslCertificate(c).subjectInfo( QSslCertificate::CommonName ) )
			.arg( c.expiryDate().toString("dd.MM.yyyy") )
			.arg( !c.isValid() ? "<font color='red'>(" + tr("expired") + ")</font>" : "" ) );
	else
		d->p12Error->setText( "<b>" + tr("Server access certificate is not installed.") + "</b>" );
	d->showP12Cert->setEnabled( !c.isNull() );
	d->showP12Cert->setProperty( "cert", QVariant::fromValue( c ) );
}
