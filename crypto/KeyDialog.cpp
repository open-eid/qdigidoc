/*
 * QDigiDocCrypto
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
#include "ui_KeyDialog.h"

#include "client/Application.h"
#include "client/FileDialog.h"
#include "client/QSigner.h"
#include "LdapSearch.h"

#include <common/IKValidator.h>
#include <common/SslCertificate.h>
#include <common/TokenData.h>

#include <QtCore/QDateTime>
#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QSettings>
#include <QtCore/QSortFilterProxyModel>
#include <QtCore/QStandardPaths>
#include <QtCore/QTextStream>
#include <QtCore/QTimer>
#include <QtCore/QXmlStreamReader>
#include <QtCore/QXmlStreamWriter>
#include <QtGui/QMouseEvent>
#include <QtNetwork/QSslKey>
#include <QtNetwork/QSslSocket>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QMessageBox>

#if QT_VERSION < 0x050700
template <class T>
constexpr typename std::add_const<T>::type& qAsConst(T& t) noexcept
{
        return t;
}
#endif

CertificateDialogEx::CertificateDialogEx(const QSslCertificate &cert, QWidget *parent)
	: CertificateDialog(cert, parent, false)
{
	QTreeWidget *view = findChild<QTreeWidget*>("pathTree");
	QTreeWidgetItem *t = new QTreeWidgetItem(view);
	view->addTopLevelItem(t);

	QList<QSslError> errors = QSslCertificate::verify(QList<QSslCertificate>() << cert);
	errors.removeAll(QSslError(QSslError::CertificateExpired, cert));
	if(errors.isEmpty())
	{
		QByteArray id = SslCertificate(cert).authorityKeyIdentifier();
		for(const QSslCertificate &ca: QSslSocket::defaultCaCertificates())
		{
			if(SslCertificate(ca).subjectKeyIdentifier() != id)
				continue;
			t->setText(0, tr("Central configuration"));
			t = new QTreeWidgetItem(t);
			t->setText(0, ca.subjectInfo("CN").join(", "));
			t = new QTreeWidgetItem(t);
			break;
		}
	}
	t->setText(0, cert.subjectInfo("CN").join(", "));
	if(!t->parent())
	{
		t->setIcon(0, style()->standardIcon(QStyle::SP_MessageBoxWarning, 0, this));
		if(QLabel *msg = findChild<QLabel*>("pathMsg"))
			msg->setText(tr("The issuer of this certificate could not be found."));
	}
	view->expandAll();
}



KeyWidget::KeyWidget( const CKey &key, int id, bool encrypted, QWidget *parent )
:	QLabel( parent )
,	m_id( id )
,	m_key( key )
{
	setWordWrap( true );
	setToolTip( key.recipient );
	connect( this, SIGNAL(linkActivated(QString)), SLOT(link(QString)) );

	QString label;
	QTextStream sc( &label );
	sc << "<p>";
	wrapKeyTokensZWSP(sc);
	sc << "</p><p align=\"right\">";
	sc << "<a href=\"details\" style=\"color: #509B00\" title=\"" << tr("Show details") << "\">" << tr("Show details") << "</a>";
	if( !encrypted )
		sc << "<br /><a href=\"remove\" style=\"color: #509B00\" title=\"" << tr("Remove") << "\">" << tr("Remove") << "</a>";
	sc << "</p>";
	setText( label );
}

void KeyWidget::link( const QString &url )
{
	if( url == "details" )
		KeyDialog( m_key, qApp->activeWindow() ).exec();
	else if( url == "remove" )
		Q_EMIT remove( m_id );
}

void KeyWidget::mouseDoubleClickEvent( QMouseEvent *e )
{
	if( e->button() == Qt::LeftButton )
		link( "details" );
}

void KeyWidget::wrapKeyTokensZWSP( QTextStream &sc )
{
	const auto keyComponents = toolTip().split(",");
	sc << keyComponents.join(",&#8203;");
}



KeyDialog::KeyDialog( const CKey &key, QWidget *parent )
:	QDialog( parent )
,	k( key )
,	d(new Ui::KeyDialog)
{
	d->setupUi( this );
	d->buttonBox->addButton( tr("Show certificate"), QDialogButtonBox::AcceptRole );

	d->title->setText( k.recipient );

	addItem( tr("Key"), k.recipient );
	addItem( tr("Crypto method"), k.method );
	if(!k.agreement.isEmpty())
		addItem(tr("Agreement method"), k.agreement);
	if(!k.derive.isEmpty())
		addItem(tr("Key derivation method"), k.derive);
	if(!k.concatDigest.isEmpty())
		addItem(tr("ConcatKDF digest method"), k.concatDigest);
	//addItem( tr("ID"), k.id );
	addItem( tr("Expires"), key.cert.expiryDate().toLocalTime().toString("dd.MM.yyyy hh:mm:ss") );
	addItem( tr("Issuer"), SslCertificate(key.cert).issuerInfo( QSslCertificate::CommonName ) );
	d->view->resizeColumnToContents( 0 );
}

KeyDialog::~KeyDialog()
{
	delete d;
}

void KeyDialog::addItem( const QString &parameter, const QString &value )
{
	QTreeWidgetItem *i = new QTreeWidgetItem( d->view );
	i->setText( 0, parameter );
	i->setText( 1, value );
	d->view->addTopLevelItem( i );
}

void KeyDialog::showCertificate()
{ CertificateDialogEx( k.cert, this ).exec(); }



HistoryModel::HistoryModel( QObject *parent )
:	QAbstractTableModel( parent )
{
	QFile f( path() );
	if( !f.open( QIODevice::ReadOnly ) )
		return;

	QXmlStreamReader xml( &f );
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
{ return parent.isValid() ? 0 : NColumns; }

QVariant HistoryModel::headerData( int section, Qt::Orientation orientation, int role ) const
{
	if( role != Qt::DisplayRole || orientation == Qt::Vertical )
		return QVariant();
	switch( section )
	{
	case Owner: return tr("Owner");
	case Type: return tr("Type");
	case Issuer: return tr("Issuer");
	case Expire: return tr("Expiry date");
	default: return QVariant();
	}
}

bool HistoryModel::insertRows( int row, int count, const QModelIndex & )
{
	//beginInsertRows( parent, row, row + count );
	for( int i = 0; i < count; ++i )
		m_data.insert( row + i, QStringList() << "" << "" << "" << "" );
	//endInsertRows();
	return true;
}

QVariant HistoryModel::data( const QModelIndex &index, int role ) const
{
	if( !hasIndex( index.row(), index.column() ) )
		return QVariant();

	QStringList row = m_data[index.row()];
	switch( role )
	{
	case Qt::DisplayRole:
		if( index.column() != Type )
			return row.value( index.column() );
		switch( row.value( Type ).toInt() )
		{
		case DigiID: return tr("DIGI-ID");
		case TEMPEL: return tr("TEMPEL");
		default: return tr("ID-CARD");
		}
	case Qt::EditRole:
		if( index.column() == Expire )
			return QDateTime::fromString( row.value( index.column() ), "dd.MM.yyyy" );
		return row.value( index.column() );
	default: return QVariant();
	}
}

QString HistoryModel::path() const
{
#ifdef Q_OS_WIN
	QSettings s( QSettings::IniFormat, QSettings::UserScope, qApp->organizationName(), "qdigidoccrypto" );
	QFileInfo f( s.fileName() );
	return f.absolutePath() + "/" + f.baseName() + "/certhistory.xml";
#else
	return QStandardPaths::writableLocation(QStandardPaths::DataLocation) + "/certhistory.xml";
#endif
}

bool HistoryModel::removeRows( int row, int count, const QModelIndex &parent )
{
	beginRemoveRows( parent, row, row + count );
	for( int i = 0; i < count; ++i )
		m_data.removeAt( row );
	endRemoveRows();
	return true;
}

int HistoryModel::rowCount( const QModelIndex &parent ) const
{ return parent.isValid() ? 0 : m_data.size(); }

bool HistoryModel::setData( const QModelIndex &index, const QVariant &value, int role )
{
	if( !hasIndex( index.row(), index.column() ) )
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

	QXmlStreamWriter xml( &f );
	xml.setAutoFormatting( true );
	xml.writeStartDocument();
	xml.writeStartElement( "History" );
	for(const QStringList &item: qAsConst(m_data))
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
{
	beginResetModel();
	certs.clear();
	endResetModel();
}

int CertModel::columnCount( const QModelIndex &index ) const
{ return index.isValid() ? 0 : NColumns; }

QVariant CertModel::headerData( int section, Qt::Orientation orientation, int role ) const
{
	if( role != Qt::DisplayRole || orientation == Qt::Vertical )
		return QVariant();
	switch( section )
	{
	case Owner: return tr("Owner");
	case Issuer: return tr("Issuer");
	case Expire: return tr("Expiry date");
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
		case Owner: return SslCertificate( certs[index.row()] ).friendlyName();
		case Issuer: return certs[index.row()].issuerInfo( QSslCertificate::CommonName );
		case Expire:
			if( role == Qt::EditRole )
				return certs[index.row()].expiryDate().toLocalTime();
			return certs[index.row()].expiryDate().toLocalTime().toString( "dd.MM.yyyy" );
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
	beginResetModel();
	certs = result;
	endResetModel();
}

int CertModel::rowCount( const QModelIndex &index ) const
{ return index.isValid() ? 0 : certs.count(); }



CertAddDialog::CertAddDialog( CryptoDoc *_doc, QWidget *parent )
:	QWidget( parent )
,	doc( _doc )
,	ldap( new LdapSearch( this ) )
{
	setupUi( this );
	setAttribute( Qt::WA_DeleteOnClose );
	setWindowFlags( Qt::Dialog );

	cardButton = buttonBox->addButton( tr("Add cert from card"), QDialogButtonBox::ActionRole );
	connect(cardButton, &QPushButton::clicked, this, &CertAddDialog::addCardCert);
	connect(buttonBox->addButton(tr("Add cert from file"), QDialogButtonBox::ActionRole),
		&QPushButton::clicked, this, &CertAddDialog::addFile);
	connect( qApp->signer(), SIGNAL(authDataChanged(TokenData)), SLOT(enableCardCert()) );
	enableCardCert();

	QSortFilterProxyModel *sort = new QSortFilterProxyModel( skView );
	sort->setSourceModel( certModel = new CertModel( this ) );
	sort->setSortRole( Qt::EditRole );
	skView->setModel( sort );
	skView->header()->setSectionResizeMode(QHeaderView::ResizeToContents);
	skView->header()->setSectionResizeMode(CertModel::Owner, QHeaderView::Stretch);
	skView->header()->setSortIndicator( 0, Qt::AscendingOrder );
	connect( skView, SIGNAL(activated(QModelIndex)), SLOT(on_add_clicked()) );

	sort = new QSortFilterProxyModel( usedView );
	sort->setSourceModel( history = new HistoryModel( sort ) );
	sort->setSortRole( Qt::EditRole );
	usedView->setModel( sort );
	usedView->header()->setSectionResizeMode(QHeaderView::ResizeToContents);
	usedView->header()->setSectionResizeMode(HistoryModel::Owner, QHeaderView::Stretch);
	usedView->header()->setSortIndicator( 0, Qt::AscendingOrder );
	connect( usedView, SIGNAL(activated(QModelIndex)), SLOT(on_find_clicked()) );

	connect( ldap, SIGNAL(searchResult(QList<QSslCertificate>)),
		SLOT(showResult(QList<QSslCertificate>)) );
	connect( ldap, SIGNAL(error(QString,QString)), SLOT(showError(QString,QString)) );

	validator = new IKValidator( this );
	on_searchType_currentIndexChanged( 0 );
	add->setEnabled( false );
	progress->setVisible( false );

	search->setDisabled( searchContent->text().isEmpty() );
	connect( searchContent, &QLineEdit::textChanged, [=](const QString &text){
		search->setDisabled( text.isEmpty() );
	});
}

void CertAddDialog::addCardCert()
{ addCerts( QList<QSslCertificate>() << qApp->signer()->tokenauth().cert() ); }

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
	else if(!SslCertificate(cert).keyUsage().contains(SslCertificate::KeyEncipherment) &&
		!SslCertificate(cert).keyUsage().contains(SslCertificate::KeyAgreement))
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
	bool status = false;
	QAbstractItemModel *m = history;
	for(const QSslCertificate &c: certs)
	{
		SslCertificate cert( c );
		if( cert.expiryDate() <= QDateTime::currentDateTime() &&
			QMessageBox::No == QMessageBox::warning( this, windowTitle(),
				tr("Are you sure that you want use certificate for encrypting, which expired on %1?<br />"
					"When decrypter has updated certificates then decrypting is impossible.")
					.arg( cert.expiryDate().toString( "dd.MM.yyyy hh:mm:ss" ) ),
				QMessageBox::Yes|QMessageBox::No, QMessageBox::No ) )
			continue;
		QList<QSslError> errors = QSslCertificate::verify(QList<QSslCertificate>() << c);
		errors.removeAll(QSslError(QSslError::CertificateExpired, c));
		if(!errors.isEmpty() &&
			QMessageBox::No == QMessageBox::warning(this, windowTitle(),
				tr("Recipient’s certification chain contains certificates that are not trusted. Continue with encryption?"),
				QMessageBox::Yes|QMessageBox::No, QMessageBox::No))
			continue;

		status = std::max( status, doc->addKey( cert ) );

		HistoryModel::KeyType type = HistoryModel::IDCard;
		switch( cert.type() )
		{
		case SslCertificate::TempelTestType:
		case SslCertificate::TempelType: type = HistoryModel::TEMPEL; break;
		case SslCertificate::DigiIDTestType:
		case SslCertificate::DigiIDType: type = HistoryModel::DigiID; break;
		case SslCertificate::EstEidTestType:
		case SslCertificate::EstEidType: type = HistoryModel::IDCard; break;
		default: continue;
		}

		bool found = false;
		for( int i = 0; i < m->rowCount(); ++i )
		{
			if( m->index( i, HistoryModel::Owner ).data().toString() == cert.subjectInfo( "CN" ) &&
				m->index( i, HistoryModel::Type ).data( Qt::EditRole ).toInt() == type )
			{
				found = true;
				break;
			}
		}
		if( found )
			continue;

		int row = m->rowCount();
		m->insertRow( row );
		m->setData( m->index( row, HistoryModel::Owner ), cert.subjectInfo( "CN" ) );
		m->setData( m->index( row, HistoryModel::Type ), type );
		m->setData( m->index( row, HistoryModel::Issuer ), cert.issuerInfo( "CN" ) );
		m->setData( m->index( row, HistoryModel::Expire ), cert.expiryDate().toLocalTime().toString( "dd.MM.yyyy" ) );
	}
	m->submit();

	Q_EMIT updateView();
	certAddStatus->setText( status ? tr("Certs added successfully") : tr("Failed to add certs") );
	QTimer::singleShot( 3*1000, certAddStatus, SLOT(clear()) );
}

void CertAddDialog::enableCardCert()
{
	cardButton->setDisabled(qApp->signer()->tokenauth().cert().isNull());
}

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
	for(const QModelIndex &index: skView->selectionModel()->selectedRows())
		certs << index.data( Qt::UserRole ).value<QSslCertificate>();
	addCerts( certs );
}

void CertAddDialog::on_remove_clicked()
{
	if( !usedView->selectionModel() || !usedView->selectionModel()->hasSelection() )
		return;
	QModelIndexList rows = usedView->selectionModel()->selectedRows();
	for( QModelIndexList::const_iterator i = rows.constEnd(); i != rows.begin(); )
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
		qApp->processEvents();
		if( searchType->currentIndex() == 1 )
			ldap->search( QString( "(cn=*%1*)" ).arg( searchContent->text() ) );
		else
			ldap->search( QString( "(serialNumber=%1)" ).arg( searchContent->text() ) );
	}
}

void CertAddDialog::on_searchType_currentIndexChanged( int index )
{
	searchContent->setValidator( index == 0 ? validator : 0 );
	certModel->clear();
	searchContent->clear();
	searchContent->setFocus();
}

void CertAddDialog::on_find_clicked()
{
	if( !usedView->selectionModel() || !usedView->selectionModel()->hasSelection() )
		return;
	QModelIndexList rows = usedView->selectionModel()->selectedRows();
	QModelIndex index = rows[0];
	QAbstractItemModel *m = usedView->model();
	QString text = m->index( index.row(), HistoryModel::Owner ).data().toString();
	tabWidget->setCurrentIndex( 0 );
	searchType->setCurrentIndex(
		m->index( index.row(), HistoryModel::Type ).data( Qt::EditRole ).toInt() == HistoryModel::TEMPEL );
	searchContent->setText( searchType->currentIndex() == 0 ? text.split( ',' ).value( 2 ) : text );
	on_search_clicked();
}

void CertAddDialog::showError( const QString &msg, const QString &details )
{
	disableSearch( false );
	QMessageBox b( QMessageBox::Warning, windowTitle(), msg );
	if( !details.isEmpty() )
		b.setDetailedText( details );
	b.exec();
}

void CertAddDialog::showResult( const QList<QSslCertificate> &result )
{
	QList<QSslCertificate> filter;
	for(const QSslCertificate &k: result)
	{
		SslCertificate c(k);
		if((c.keyUsage().contains(SslCertificate::KeyEncipherment) ||
			c.keyUsage().contains(SslCertificate::KeyAgreement)) &&
			!c.enhancedKeyUsage().contains(SslCertificate::ServerAuth) &&
			(searchType->currentIndex() == 0 || !c.enhancedKeyUsage().contains(SslCertificate::ClientAuth)) &&
			c.type() != SslCertificate::MobileIDType)
			filter << c;
	}
	certModel->load(filter);

	disableSearch( false );
	add->setEnabled( true );

	if( certModel->rowCount() )
	{
		skView->setCurrentIndex( skView->model()->index( 0, CertModel::Owner ) );
		if( searchType->currentIndex() == 0 )
			skView->selectAll();
		add->setFocus();
	}
	else
		showError( tr("Person or company does not own a valid certificate.<br />"
			"It is necessary to have a valid certificate for encryption.<br />"
			"Contact for assistance by email <a href=\"mailto:abi@id.ee\">abi@id.ee</a> "
			"or call 1777 (only from Estonia), (+372) 677 3377 when calling from abroad.") );
}
