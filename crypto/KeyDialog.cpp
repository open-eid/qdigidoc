/*
 * QDigiDocCrypto
 *
 * Copyright (C) 2009-2012 Jargo Kõster <jargo@innovaatik.ee>
 * Copyright (C) 2009-2012 Raul Metsma <raul@innovaatik.ee>
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

#include "KeyDialog.h"

#include "Application.h"
#include "LdapSearch.h"
#include "Poller.h"

#include <common/CertificateWidget.h>
#include <common/FileDialog.h>
#include <common/IKValidator.h>
#include <common/SslCertificate.h>
#include <common/TokenData.h>

#include <QtCore/QDateTime>
#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QSettings>
#include <QtCore/QTimer>
#include <QtCore/QXmlStreamReader>
#include <QtCore/QXmlStreamWriter>
#include <QtGui/QHeaderView>
#include <QtGui/QMessageBox>

Q_DECLARE_METATYPE( QSslCertificate )

KeyWidget::KeyWidget( const CKey &key, int id, bool encrypted, QWidget *parent )
:	QWidget( parent )
,	m_id( id )
,	m_key( key )
{
	setToolTip( key.recipient );
	QLabel *label = new QLabel( key.recipient, this );
	label->setWordWrap( true );
	label->setSizePolicy( QSizePolicy::Ignored, QSizePolicy::Preferred );

	QString content;
	content += "<a href=\"details\">" + tr("Show details") + "</a>";
	if( !encrypted )
		content += "<br /><a href=\"remove\">" + tr("Remove") + "</a>";
	QLabel *btn = new QLabel( content, this );
	btn->setAlignment( Qt::AlignRight );
	connect( btn, SIGNAL(linkActivated(QString)), SLOT(link(QString)) );

	QVBoxLayout *l = new QVBoxLayout( this );
	l->addWidget( label );
	l->addWidget( btn );
}

void KeyWidget::link( const QString &url )
{
	if( url == "details" )
		(new KeyDialog( m_key, qApp->activeWindow() ))->show();
	else if( url == "remove" )
		Q_EMIT remove( m_id );
}



KeyDialog::KeyDialog( const CKey &key, QWidget *parent )
:	QWidget( parent )
,	k( key )
{
	setupUi( this );
	setAttribute( Qt::WA_DeleteOnClose );
	setWindowFlags( Qt::Dialog );
	buttonBox->addButton( tr("Show certificate"), QDialogButtonBox::AcceptRole );

	title->setText( k.recipient );

	addItem( tr("Key"), k.recipient );
	addItem( tr("Crypt method"), k.type );
	//addItem( tr("ID"), k.id );
	addItem( tr("Expires"), key.cert.expiryDate().toLocalTime().toString("dd.MM.yyyy hh:mm:ss") );
	addItem( tr("Issuer"), key.cert.issuerInfo( QSslCertificate::CommonName ) );
	view->resizeColumnToContents( 0 );
}

void KeyDialog::addItem( const QString &parameter, const QString &value )
{
	QTreeWidgetItem *i = new QTreeWidgetItem( view );
	i->setText( 0, parameter );
	i->setText( 1, value );
	view->addTopLevelItem( i );
}

void KeyDialog::showCertificate()
{ CertificateDialog( k.cert, this ).exec(); }



HistoryModel::HistoryModel( QObject *parent )
:	QAbstractTableModel( parent )
{
	QFile f( path() );
	if( !f.open( QIODevice::ReadOnly ) )
		return;

	QXmlStreamReader xml;
	xml.setDevice( &f );

	if( !xml.readNextStartElement() || xml.name() != "History" )
		return;

	while( xml.readNextStartElement() )
	{
		if( xml.name() == "item" )
		{
			m_data << (QStringList()
				<< xml.attributes().value( "CN" ).toString()
				<< xml.attributes().value( "type" ).toString()
				<< xml.attributes().value( "issuer" ).toString()
				<< xml.attributes().value( "expireDate" ).toString());
		}
		xml.skipCurrentElement();
	}
}

int HistoryModel::columnCount( const QModelIndex &parent ) const
{ return parent.isValid() ? 0 : 4; }

QVariant HistoryModel::headerData( int section, Qt::Orientation orientation, int role ) const
{
	if( role != Qt::DisplayRole || orientation == Qt::Vertical )
		return QVariant();
	switch( section )
	{
	case 0: return tr("Owner");
	case 1: return tr("Type");
	case 2: return tr("Issuer");
	case 3: return tr("Expiry date");
	default: return QVariant();
	}
}

bool HistoryModel::insertRows( int row, int count, const QModelIndex &parent )
{
	beginInsertRows( parent, row, row + count );
	for( int i = 0; i < count; ++i )
		m_data.insert( row + i, QStringList() << "" << "" << "" << "" );
	endInsertRows();
	return true;
}

QVariant HistoryModel::data( const QModelIndex &index, int role ) const
{
	if( !index.isValid() || index.row() >= m_data.size() )
		return QVariant();

	QStringList row = m_data[index.row()];
	switch( role )
	{
	case Qt::DisplayRole:
		if( index.column() != 1 )
			return row.value( index.column() );
		switch( row.value( 1 ).toInt() )
		{
		case DigiID: return tr("DIGI-ID");
		case TEMPEL: return tr("TEMPEL");
		default: return tr("ID-CARD");
		}
	case Qt::EditRole: return row.value( index.column() );
	default: return QVariant();
	}
}

QString HistoryModel::path() const
{
	QSettings s( QSettings::IniFormat, QSettings::UserScope, qApp->organizationName(), qApp->applicationName() );
	QFileInfo f( s.fileName() );
	return f.absolutePath() + "/" + f.baseName() + "/certhistory.xml";
}

bool HistoryModel::removeRows( int row, int count, const QModelIndex &parent )
{
	beginRemoveRows( parent, row, row + count );
	for( int i = row + count - 1; i >= row; --i )
		m_data.removeAt( i );
	endInsertRows();
	return true;
}

int HistoryModel::rowCount( const QModelIndex &parent ) const
{ return parent.isValid() ? 0 : m_data.size(); }

bool HistoryModel::setData( const QModelIndex &index, const QVariant &value, int role )
{
	if( !index.isValid() || index.row() >= m_data.size() )
		return false;
	switch( role )
	{
	case Qt::EditRole:
		m_data[index.row()][index.column()] = value.toString();
		Q_EMIT dataChanged( index, index );
		return true;
	default: return false;
	}
}

bool HistoryModel::submit()
{
	QString p = path();
	QDir().mkpath( QFileInfo( p ).absolutePath() );
	QFile f( p );
	if( !f.open( QIODevice::WriteOnly|QIODevice::Truncate ) )
		return false;

	QXmlStreamWriter xml;
	xml.setDevice( &f );
	xml.setAutoFormatting( true );
	xml.writeStartDocument();
	xml.writeStartElement( "History" );
	Q_FOREACH( const QStringList &item, m_data )
	{
		xml.writeStartElement( "item" );
		xml.writeAttribute( "CN", item.value(0) );
		xml.writeAttribute( "type", item.value(1) );
		xml.writeAttribute( "issuer", item.value(2) );
		xml.writeAttribute( "expireDate", item.value(3) );
		xml.writeEndElement();
	}
	xml.writeEndDocument();

	return true;
}



CertModel::CertModel( QObject *parent )
:	QAbstractTableModel( parent )
{}

void CertModel::clear()
{ certs.clear(); reset(); }

int CertModel::columnCount( const QModelIndex &index ) const
{ return index.isValid() ? 0 : 3; }

QVariant CertModel::headerData( int section, Qt::Orientation orientation, int role ) const
{
	if( role != Qt::DisplayRole || orientation == Qt::Vertical )
		return QVariant();
	switch( section )
	{
	case 0: return tr("Owner");
	case 1: return tr("Issuer");
	case 2: return tr("Expiry date");
	default: return QVariant();
	}
}

QVariant CertModel::data( const QModelIndex &index, int role ) const
{
	if( !hasIndex( index.row(), index.column() ) )
		return QVariant();

	switch( role )
	{
	case Qt::DisplayRole:
	case Qt::EditRole:
		switch( index.column() )
		{
		case 0: return SslCertificate( certs[index.row()] ).friendlyName();
		case 1: return certs[index.row()].issuerInfo( QSslCertificate::CommonName );
		case 2: return certs[index.row()].expiryDate().toLocalTime().toString( "dd.MM.yyyy" );
		default: break;
		}
	case Qt::UserRole:
		return QVariant::fromValue( certs[index.row()] );
	default: break;
	}
	return QVariant();
}

void CertModel::load( const QList<QSslCertificate> &result )
{
	certs.clear();
	Q_FOREACH( const QSslCertificate &k, result )
	{
		SslCertificate c( k );
		if( c.keyUsage().contains( SslCertificate::KeyEncipherment ) &&
			c.type() != SslCertificate::MobileIDType )
			certs << c;
	}
	reset();
}

int CertModel::rowCount( const QModelIndex &index ) const
{ return index.isValid() ? 0 : certs.count(); }



CertAddDialog::CertAddDialog( CryptoDoc *_doc, QWidget *parent )
:	QWidget( parent )
,	doc( _doc )
{
	setupUi( this );
	setAttribute( Qt::WA_DeleteOnClose );
	setWindowFlags( Qt::Dialog );

	cardButton = buttonBox->addButton( tr("Add cert from card"), QDialogButtonBox::ActionRole );
	connect( cardButton, SIGNAL(clicked()), SLOT(addCardCert()) );
	connect( buttonBox->addButton( tr("Add cert from file"), QDialogButtonBox::ActionRole ),
		SIGNAL(clicked()), SLOT(addFile()) );
	connect( qApp->poller(), SIGNAL(dataChanged()), SLOT(enableCardCert()) );
	enableCardCert();

	skView->setModel( certModel = new CertModel( this ) );
	skView->header()->setStretchLastSection( false );
	skView->header()->setResizeMode( QHeaderView::ResizeToContents );
	skView->header()->setResizeMode( 0, QHeaderView::Stretch );
	connect( skView, SIGNAL(doubleClicked(QModelIndex)), SLOT(on_add_clicked()) );

	usedView->setModel( new HistoryModel( this ) );
	usedView->header()->setStretchLastSection( false );
	usedView->header()->setResizeMode( QHeaderView::ResizeToContents );
	usedView->header()->setResizeMode( 0, QHeaderView::Stretch );

	ldap = new LdapSearch( this );
	connect( ldap, SIGNAL(searchResult(QList<QSslCertificate>)),
		SLOT(showResult(QList<QSslCertificate>)) );
	connect( ldap, SIGNAL(error(QString)), SLOT(showError(QString)) );

	validator = new IKValidator( this );
	on_searchType_currentIndexChanged( 0 );
	add->setEnabled( false );
	progress->setVisible( false );
}

void CertAddDialog::addCardCert()
{ addCerts( QList<QSslCertificate>() << qApp->poller()->token().cert() ); }

void CertAddDialog::addFile()
{
	QString file = FileDialog::getOpenFileName( this, windowTitle(), QString(),
		tr("Certificates (*.pem *.cer *.crt)") );
	if( file.isEmpty() )
		return;

	QFile f( file );
	if( !f.open( QIODevice::ReadOnly ) )
	{
		QMessageBox::warning( this, windowTitle(), tr("Failed to open certifiacte") );
		return;
	}

	QSslCertificate cert( &f, QSsl::Pem );
	if( cert.isNull() )
	{
		f.reset();
		cert = QSslCertificate( &f, QSsl::Der );
	}
	if( cert.isNull() )
	{
		QMessageBox::warning( this, windowTitle(), tr("Failed to read certificate") );
	}
	else if( !SslCertificate( cert ).keyUsage().contains( SslCertificate::KeyEncipherment ) )
	{
		QMessageBox::warning( this, windowTitle(), tr("This certificate is not usable for crypting") );
	}
	else
		addCerts( QList<QSslCertificate>() << cert );

	f.close();
}

void CertAddDialog::addCerts( const QList<QSslCertificate> &certs )
{
	if( certs.isEmpty() )
		return;
	bool status = true;
	QAbstractItemModel *m = usedView->model();
	Q_FOREACH( const QSslCertificate &c, certs )
	{
		SslCertificate cert( c );
		if( cert.expiryDate() <= QDateTime::currentDateTime() &&
			QMessageBox::No == QMessageBox::warning( this, windowTitle(),
				tr("Are you sure that you want use certificate for encrypting, which expired on %1?<br />"
					"When decrypter has updated certificates then decrypting is impossible.")
					.arg( cert.expiryDate().toString( "dd.MM.yyyy hh:mm:ss" ) ),
				QMessageBox::Yes|QMessageBox::No, QMessageBox::No ) )
			continue;
		status = qMin( status, doc->addKey( cert ) );

		HistoryModel::KeyType type = HistoryModel::IDCard;
		switch( cert.type() )
		{
		case SslCertificate::TempelType: type = HistoryModel::TEMPEL; break;
		case SslCertificate::DigiIDTestType:
		case SslCertificate::DigiIDType: type = HistoryModel::DigiID; break;
		case SslCertificate::EstEidTestType:
		case SslCertificate::EstEidType: type = HistoryModel::IDCard; break;
		default: continue;
		}

		if( !m->match( m->index( 0, 0 ), Qt::DisplayRole, cert.subjectInfo( "CN" ), 1, Qt::MatchExactly ).isEmpty() &&
			!m->match( m->index( 0, 1 ), Qt::EditRole, type, 1, Qt::MatchExactly ).isEmpty() )
			continue;

		int row = m->rowCount();
		m->insertRow( row );
		m->setData( m->index( row, 0 ), cert.subjectInfo( "CN" ) );
		m->setData( m->index( row, 1 ), type );
		m->setData( m->index( row, 2 ), cert.issuerInfo( "CN" ) );
		m->setData( m->index( row, 3 ), cert.expiryDate().toLocalTime().toString( "dd.MM.yyyy" ) );
	}
	m->submit();

	Q_EMIT updateView();
	certAddStatus->setText( status ? tr("Certs added successfully") : tr("Failed to add certs") );
	QTimer::singleShot( 3*1000, certAddStatus, SLOT(hide()) );
}

void CertAddDialog::enableCardCert() { cardButton->setDisabled( qApp->poller()->token().cert().isNull() ); }

void CertAddDialog::disableSearch( bool disable )
{
	progress->setVisible( disable );
	search->setDisabled( disable );
	skView->setDisabled( disable );
	searchType->setDisabled( disable );
	searchContent->setDisabled( disable );
}

void CertAddDialog::on_add_clicked()
{
	if( !skView->selectionModel()->hasSelection() )
		return;
	QList<QSslCertificate> certs;
	Q_FOREACH( const QModelIndex &index, skView->selectionModel()->selectedRows() )
		certs << index.data( Qt::UserRole ).value<QSslCertificate>();
	addCerts( certs );
}

void CertAddDialog::on_remove_clicked()
{
	QModelIndexList rows = usedView->selectionModel()->selectedRows();
	for( QModelIndexList::const_iterator i = rows.constEnd(); i > rows.begin(); )
	{
		--i;
		usedView->model()->removeRow( i->row() );
	}
	usedView->model()->submit();
}

void CertAddDialog::on_search_clicked()
{
	if( searchType->currentIndex() == 0 &&
		!IKValidator::isValid( searchContent->text() ) )
	{
		QMessageBox::warning( this, windowTitle(),
			tr("Social security number is not valid!") );
	}
	else
	{
		certModel->clear();
		add->setEnabled( false );
		disableSearch( true );
		if( searchType->currentIndex() == 0 )
			ldap->search( QString( "(serialNumber=%1)" ).arg( searchContent->text() ) );
		else
			ldap->search( QString( "(cn=*%1*)" ).arg( searchContent->text() ) );
	}
}

void CertAddDialog::on_searchType_currentIndexChanged( int index )
{
	searchContent->setValidator( index == 0 ? validator : 0 );
	certModel->clear();
	searchContent->clear();
	searchContent->setFocus();
}

void CertAddDialog::on_usedView_doubleClicked( const QModelIndex &index )
{
	QAbstractItemModel *m = usedView->model();
	QString text = m->index( index.row(), 0 ).data().toString();
	tabWidget->setCurrentIndex( 0 );
	searchType->setCurrentIndex(
		m->index( index.row(), 1 ).data( Qt::EditRole ).toInt() == HistoryModel::TEMPEL );
	searchContent->setText( searchType->currentIndex() == 0 ? text.split( ',' ).value( 2 ) : text );
	on_search_clicked();
}

void CertAddDialog::showError( const QString &msg )
{
	disableSearch( false );
	QMessageBox::warning( this, windowTitle(), msg );
}

void CertAddDialog::showResult( const QList<QSslCertificate> &result )
{
	certModel->load( result );

	disableSearch( false );
	add->setEnabled( true );

	if( certModel->rowCount() )
	{
		skView->setCurrentIndex( skView->model()->index( 0, 0 ) );
		if( searchType->currentIndex() == 0 )
			skView->selectAll();
		add->setFocus();
	}
	else
		showError( tr("Person or company does not own a valid certificate.\n"
			"It is necessary to have a valid certificate for encryption.") );
}
