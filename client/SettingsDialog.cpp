/*
 * QDigiDocClient
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
#include "FileDialog.h"

#include <common/CertificateWidget.h>
#include <common/Settings.h>
#include <common/SslCertificate.h>
#include <common/TokenData.h>

#include <digidocpp/Conf.h>

#include <QtCore/QDateTime>
#include <QtCore/QUrl>
#include <QtGui/QDropEvent>
#include <QtGui/QDesktopServices>
#include <QtNetwork/QNetworkProxy>
#if QT_VERSION >= 0x050000
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QInputDialog>
#else
#include <QtGui/QMessageBox>
#endif

#if QT_VERSION < 0x050000
Q_DECLARE_METATYPE(QSslCertificate)
#endif

SettingsDialog::SettingsDialog( int page, QWidget *parent )
:	QDialog( parent )
,	d( new Ui::SettingsDialog )
{
	d->setupUi( this );
	d->tabWidget->setCurrentIndex( page );
	setAttribute( Qt::WA_DeleteOnClose );
	Common::setAccessibleName( d->p12Label );

	Settings s2(qApp->applicationName());
	Settings s;
	d->showIntro->setChecked( s2.value( "ClientIntro", true ).toBool() );
	d->showIntro2->setChecked( s.value( "Crypto/Intro", true ).toBool() );
	d->cdocwithddoc->setChecked( s2.value( "cdocwithddoc", false ).toBool() );
	connect(d->cdocwithddoc, &QCheckBox::toggled, [](bool checked){
		Settings(qApp->applicationName()).setValueEx( "cdocwithddoc", checked, false );
	});
	s.beginGroup( "Client" );
	// Cleanup old keys
	s.remove( "lastPath" );
	s.remove( "type" );
	s.remove( "Intro" );
	s2.remove( "Intro" );
	updateCert();
#ifdef Q_OS_MAC
	d->p12Label->setText( tr(
		"Regarding to terms and conditions of validity confirmation service you're "
		"allowed to use the service in extent of 10 signatures per month. Additional "
		"information is available from <a href=\"http://www.id.ee/kehtivuskinnitus\">"
		"http://www.id.ee/kehtivuskinnitus</a> or phone 1777 (only from Estonia), (+372) 6773377") );
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

	d->tabSigningLayout->setAlignment( d->typeBDoc, Qt::AlignTop );
	d->tabSigningLayout->setAlignment( d->typeASIC, Qt::AlignTop );
	QButtonGroup *type = new QButtonGroup( this );
	QStringList list( {"bdoc", "asice"} );
	type->addButton( d->typeBDoc, 0 );
	type->addButton( d->typeASIC, 1 );
	int pos = list.indexOf(s2.value( "type", "bdoc" ).toString());
	if( pos != -1 )
		type->button( pos )->setChecked( true );
	connect( type, static_cast<void (QButtonGroup::*)(int, bool)>(&QButtonGroup::buttonToggled), [=]( int index, bool toggled ) {
		if( toggled )
			Settings(qApp->applicationName()).setValueEx( "type", list.at( index ), "bdoc" );
	});

	d->TSLOnlineDigest->setChecked( qApp->confValue( Application::TSLOnlineDigest ).toBool() );
	connect( d->TSLOnlineDigest, &QCheckBox::toggled, []( bool checked ) {
		qApp->setConfValue( Application::TSLOnlineDigest, checked );
	});

	d->tokenRestart->hide();
#ifdef Q_OS_WIN
	connect( d->tokenRestart, &QPushButton::clicked, []{
		qApp->setProperty("restart", true);
		qApp->quit();
	});
	d->tokenBackend->setChecked(Settings(qApp->applicationName()).value("tokenBackend").toUInt());
	connect( d->tokenBackend, &QCheckBox::toggled, [=](bool checked){
		Settings(qApp->applicationName()).setValueEx("tokenBackend", int(checked), 0);
		d->tokenRestart->show();
	});
#else
	d->tokenBackend->hide();
#endif

	d->signRoleInput->setText( s.value( "Role" ).toString() );
	d->signResolutionInput->setText( s.value( "Resolution" ).toString() );
	d->signCityInput->setText( s.value( "City" ).toString() );
	d->signStateInput->setText( s.value( "State" ).toString() );
	d->signCountryInput->setText( s.value( "Country" ).toString() );
	d->signZipInput->setText( s.value( "Zip" ).toString() );

	d->signOverwrite->setChecked( s.value( "Overwrite", false ).toBool() );
	d->proxyConfig->setId(d->proxyDisabled, 0);
	d->proxyConfig->setId(d->proxyAuto, 1);
	d->proxyConfig->setId(d->proxyManual, 2);
	if( QAbstractButton *b = d->proxyConfig->button( s2.value("proxyConfig", 0 ).toInt() ) )
		b->setChecked( true );
	updateProxy();
	d->p12Ignore->setChecked( Application::confValue( Application::PKCS12Disable, false ).toBool() );

	s.endGroup();
}

SettingsDialog::~SettingsDialog() { delete d; }

void SettingsDialog::activateAccessCert( const QString &certpath )
{
	d->tabWidget->setCurrentIndex( AccessCertSettings );
	QFile file( !certpath.isEmpty() ? certpath :
		FileDialog::getOpenFileName( this, tr("Select server access certificate"),
		QString(), tr("Server access certificates (*.p12 *.p12d *.pfx)") ) );
	if(!file.exists())
		return;
	QString pass = QInputDialog::getText( this, tr("Password"),
		tr("Enter server access certificate password."), QLineEdit::Password );
	if(pass.isEmpty())
		return;

	if(!file.open(QFile::ReadOnly))
		return;

	PKCS12Certificate p12(&file, pass);
	switch(p12.error())
	{
	case PKCS12Certificate::NullError: break;
	case PKCS12Certificate::InvalidPasswordError:
		QMessageBox::warning(this, tr("Select server access certificate"), tr("Invalid password"));
		return;
	default:
		QMessageBox::warning(this, tr("Select server access certificate"),
			tr("Server access certificate error: %1").arg(p12.errorString()));
		return;
	}

#ifndef Q_OS_MAC
	if( file.fileName() == QDir::fromNativeSeparators( Application::confValue( Application::PKCS12Cert ).toString() ) )
		return;
#endif
	file.reset();
	AccessCert().installCert( file.readAll(), pass );
	updateCert();
}

void SettingsDialog::loadProxy( const digidoc::Conf *conf )
{
	switch(Settings(qApp->applicationName()).value("proxyConfig", 0).toUInt())
	{
	case 0:
		QNetworkProxyFactory::setUseSystemConfiguration(false);
		QNetworkProxy::setApplicationProxy(QNetworkProxy());
		break;
	case 1:
		QNetworkProxyFactory::setUseSystemConfiguration(true);
		break;
	default:
		QNetworkProxyFactory::setUseSystemConfiguration(false);
		QNetworkProxy::setApplicationProxy(QNetworkProxy(QNetworkProxy::HttpProxy,
			QString::fromStdString(conf->proxyHost()),
			QString::fromStdString(conf->proxyPort()).toUInt(),
			QString::fromStdString(conf->proxyUser()),
			QString::fromStdString(conf->proxyPass())));
		break;
	}
}

void SettingsDialog::on_p12Install_clicked()
{
	activateAccessCert();
}

void SettingsDialog::on_p12Remove_clicked()
{
	AccessCert().remove();
	updateCert();
}

void SettingsDialog::on_selectDefaultDir_clicked()
{
#ifndef Q_OS_MAC
	QString dir = Settings().value( "Client/DefaultDir" ).toString();
	dir = FileDialog::getExistingDirectory( this, tr("Select folder"), dir );
	if( !dir.isEmpty() )
	{
		Settings().setValueEx( "Client/DefaultDir", dir, QString() );
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

void SettingsDialog::save()
{
	Settings s;
	s.setValueEx( "Crypto/Intro", d->showIntro2->isChecked(), true );
	Settings(qApp->applicationName()).setValue( "ClientIntro", d->showIntro->isChecked() );
	s.beginGroup( "Client" );
	s.setValueEx( "Overwrite", d->signOverwrite->isChecked(), false );
#ifndef Q_OS_MAC
	s.setValueEx( "AskSaveAs", d->askSaveAs->isChecked(), true );
	if( d->defaultSameDir->isChecked() )
	{
		d->defaultDir->clear();
		s.remove( "DefaultDir" );
	}
#endif
	Settings(qApp->applicationName()).setValueEx("proxyConfig", d->proxyConfig->checkedId(), 0);
	Application::setConfValue( Application::ProxyHost, d->proxyHost->text() );
	Application::setConfValue( Application::ProxyPort, d->proxyPort->text() );
	Application::setConfValue( Application::ProxyUser, d->proxyUser->text() );
	Application::setConfValue( Application::ProxyPass, d->proxyPass->text() );
	Application::setConfValue( Application::ProxySSL, d->proxySSL->isChecked() );
	Application::setConfValue( Application::PKCS12Disable, d->p12Ignore->isChecked() );
	loadProxy(digidoc::Conf::instance());
	updateProxy();

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
		s.setValueEx( "Role", role, QString() );
		s.setValueEx( "Resolution", resolution, QString() );
		s.setValueEx( "City", city, QString() );
		s.setValueEx( "State", state, QString() ),
		s.setValueEx( "Country", country, QString() );
		s.setValueEx( "Zip", zip, QString() );
	}
	s.endGroup();
}

void SettingsDialog::updateCert()
{
	QSslCertificate c = AccessCert::cert();
	if( !c.isNull() )
		d->p12Error->setText( tr("Issued to: %1<br />Valid to: %2 %3")
			.arg( SslCertificate(c).subjectInfo( QSslCertificate::CommonName ) )
			.arg( c.expiryDate().toString("dd.MM.yyyy") )
			.arg( !SslCertificate(c).isValid() ? "<font color='red'>(" + tr("expired") + ")</font>" : "" ) );
	else
		d->p12Error->setText( "<b>" + tr("Server access certificate is not installed.") + "</b>" );
	d->showP12Cert->setEnabled( !c.isNull() );
	d->showP12Cert->setProperty( "cert", QVariant::fromValue( c ) );
}

void SettingsDialog::updateProxy()
{
	d->proxyHost->setEnabled(d->proxyConfig->checkedId() == 2);
	d->proxyPort->setEnabled(d->proxyConfig->checkedId() == 2);
	d->proxyUser->setEnabled(d->proxyConfig->checkedId() == 2);
	d->proxyPass->setEnabled(d->proxyConfig->checkedId() == 2);
	d->proxyHost->setText(Application::confValue( Application::ProxyHost ).toString());
	d->proxyPort->setText(Application::confValue( Application::ProxyPort ).toString());
	d->proxyUser->setText(Application::confValue( Application::ProxyUser ).toString());
	d->proxyPass->setText(Application::confValue( Application::ProxyPass ).toString());
	d->proxySSL->setChecked(Application::confValue( Application::ProxySSL ).toBool());
}
