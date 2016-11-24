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

#include "DigiDoc.h"

#include "Application.h"
#include "FileDialog.h"
#include "QSigner.h"

#include <common/Settings.h>
#include <common/SslCertificate.h>
#include <common/TokenData.h>

#include <digidocpp/DataFile.h>
#include <digidocpp/Signature.h>
#include <digidocpp/crypto/X509Cert.h>

#include <QtCore/QDateTime>
#include <QtCore/QDir>
#include <QtCore/QFileInfo>
#include <QtCore/QMimeData>
#include <QtCore/QProcessEnvironment>
#include <QtCore/QStringList>
#include <QtCore/QUrl>
#include <QtGui/QDesktopServices>
#include <QtGui/QPixmap>
#include <QtWidgets/QMessageBox>

#include <cmath>
#include <stdexcept>

using namespace digidoc;

static std::string to( const QString &str ) { return std::string( str.toUtf8().constData() ); }
static QString from( const std::string &str ) { return QString::fromUtf8( str.c_str() ).normalized( QString::NormalizationForm_C ); }
static QByteArray fromVector( const std::vector<unsigned char> &d )
{ return d.empty() ? QByteArray() : QByteArray( (const char *)&d[0], int(d.size()) ); }



DocumentModel::DocumentModel( DigiDoc *doc )
:	QAbstractTableModel( doc )
,	d( doc )
{
}

int DocumentModel::columnCount( const QModelIndex &parent ) const
{ return parent.isValid() ? 0 : NColumns; }

QString DocumentModel::save( const QModelIndex &index, const QString &path ) const
{
	if( !hasIndex( index.row(), index.column() ) )
		return QString();
	QFile::remove( path );
	d->b->dataFiles().at( index.row() )->saveAs( path.toUtf8().constData() );
	return path;
}

QVariant DocumentModel::data( const QModelIndex &index, int role ) const
{
	if( !hasIndex( index.row(), index.column() ) )
		return QVariant();

	const DataFile *file = d->b->dataFiles().at( index.row() );
	switch( role )
	{
	case Qt::ForegroundRole:
		switch( index.column() )
		{
		case Size: return QColor(Qt::gray);
		default: return QVariant();
		}
	case Qt::DisplayRole:
		switch( index.column() )
		{
		case Id: return QString::fromUtf8( file->id().c_str() );
		case Name: return from( file->fileName() );
		case Mime: return from( file->mediaType() );
		case Size: return FileDialog::fileSize( file->fileSize() );
		default: return QVariant();
		}
	case Qt::TextAlignmentRole:
		switch( index.column() )
		{
		case Name:
		case Mime: return int(Qt::AlignLeft|Qt::AlignVCenter);
		case Size: return int(Qt::AlignRight|Qt::AlignVCenter);
		default: return Qt::AlignCenter;
		}
	case Qt::ToolTipRole:
		switch( index.column() )
		{
		case Save: return tr("Save");
		case Remove: return tr("Remove");
		default: return tr("Filename: %1\nFilesize: %2\nMedia type: %3")
			.arg( from( file->fileName() ) )
			.arg( FileDialog::fileSize( file->fileSize() ) )
			.arg( from( file->mediaType() ) );
		}
	case Qt::DecorationRole:
		switch( index.column() )
		{
		case Save: return QPixmap(":/images/ico_save.png");
		case Remove: return QPixmap(":/images/ico_delete.png");
		default: return QVariant();
		}
	case Qt::SizeHintRole:
		switch( index.column() )
		{
		case Save:
		case Remove: return QSize( 20, 20 );
		default: return QVariant();
		}
	case Qt::UserRole:
		return FileDialog::safeName(from(file->fileName()));
	default: return QVariant();
	}
}

Qt::ItemFlags DocumentModel::flags( const QModelIndex & ) const
{ return Qt::ItemIsEnabled | Qt::ItemIsSelectable | Qt::ItemIsDragEnabled; }

QMimeData* DocumentModel::mimeData( const QModelIndexList &indexes ) const
{
	QList<QUrl> list;
	Q_FOREACH( const QModelIndex &index, indexes )
	{
		if( index.column() != 0 )
			continue;
		QString path = save( index, FileDialog::tempPath(index.data(Qt::UserRole).toString()) );
		if( !path.isEmpty() )
			list << QUrl::fromLocalFile( QFileInfo( path ).absoluteFilePath() );
	}
	QMimeData *data = new QMimeData();
	data->setUrls( list );
	return data;
}

QStringList DocumentModel::mimeTypes() const
{ return QStringList() << "text/uri-list"; }

void DocumentModel::open( const QModelIndex &index )
{
	QFileInfo f( save( index, FileDialog::tempPath(index.data(Qt::UserRole).toString()) ) );
	if( !f.exists() )
		return;
	d->m_tempFiles << f.absoluteFilePath();
#if defined(Q_OS_WIN)
	QStringList exts = QProcessEnvironment::systemEnvironment().value( "PATHEXT" ).split( ';' );
	exts << ".PIF" << ".SCR";
	if( exts.contains( "." + f.suffix(), Qt::CaseInsensitive ) &&
		QMessageBox::warning( qApp->activeWindow(), tr("DigiDoc3 client"),
			tr("This is an executable file! "
				"Executable files may contain viruses or other malicious code that could harm your computer. "
				"Are you sure you want to launch this file?"),
			QMessageBox::Yes|QMessageBox::No, QMessageBox::No ) == QMessageBox::No )
		return;
#else
	QFile::setPermissions( f.absoluteFilePath(), QFile::Permissions(0x6000) );
#endif
	QDesktopServices::openUrl( QUrl::fromLocalFile( f.absoluteFilePath() ) );
}

bool DocumentModel::removeRows( int row, int count, const QModelIndex &parent )
{
	if( !d->b || parent.isValid() )
		return false;

	try
	{
		beginRemoveRows( parent, row, row + count );
		for( int i = row + count - 1; i >= row; --i )
			d->b->removeDataFile( i );
		endRemoveRows();
		return true;
	}
	catch( const Exception &e ) { d->setLastError( tr("Failed remove document from container"), e ); }
	return false;
}

void DocumentModel::reset()
{
	beginResetModel();
	endResetModel();
}

int DocumentModel::rowCount( const QModelIndex &parent ) const
{ return !d->b || parent.isValid() ? 0 : int(d->b->dataFiles().size()); }

Qt::DropActions DocumentModel::supportedDragActions() const
{
	return  Qt::CopyAction;
}



DigiDocSignature::DigiDocSignature( const digidoc::Signature *signature, DigiDoc *parent )
:	s(signature)
,	m_lastErrorCode(-1)
,	m_parent(parent)
,	m_warning(0)
{}

QSslCertificate DigiDocSignature::cert() const
{
	try
	{
		return QSslCertificate( fromVector(s->signingCertificate()), QSsl::Der );
	}
	catch( const Exception & ) {}
	return QSslCertificate();
}

QDateTime DigiDocSignature::dateTime() const
{
	QDateTime ts = tsTime();
	if(!ts.isNull()) return ts;
	QDateTime ocsp = ocspTime();
	if(!ocsp.isNull()) return ocsp;
	return signTime();
}

QString DigiDocSignature::lastError() const { return m_lastError; }
int DigiDocSignature::lastErrorCode() const { return m_lastErrorCode; }

QString DigiDocSignature::location() const
{
	QStringList l = locations();
	l.removeAll( "" );
	return l.join( ", " );
}

QStringList DigiDocSignature::locations() const
{
	return QStringList()
		<< from( s->city() ).trimmed()
		<< from( s->stateOrProvince() ).trimmed()
		<< from( s->postalCode() ).trimmed()
		<< from( s->countryName() ).trimmed();
}

QSslCertificate DigiDocSignature::ocspCert() const
{
	return QSslCertificate(
		fromVector(s->OCSPCertificate()), QSsl::Der );
}

QByteArray DigiDocSignature::ocspNonce() const
{
	return fromVector(s->OCSPNonce());
}

QDateTime DigiDocSignature::ocspTime() const
{
	QString dateTime = from( s->OCSPProducedAt() );
	if( dateTime.isEmpty() )
		return QDateTime();
	QDateTime date = QDateTime::fromString( dateTime, "yyyy-MM-dd'T'hh:mm:ss'Z'" );
	date.setTimeSpec( Qt::UTC );
	return date;
}

DigiDoc* DigiDocSignature::parent() const { return m_parent; }

void DigiDocSignature::parseException( DigiDocSignature::SignatureStatus &result, const digidoc::Exception &e ) const
{
	Q_FOREACH( const Exception &child, e.causes() )
	{
		switch( child.code() )
		{
		case Exception::ReferenceDigestWeak:
		case Exception::SignatureDigestWeak:
			m_warning |= DigestWeak;
			result = std::max( result, Warning );
			break;
		case Exception::DataFileNameSpaceWarning:
			m_warning |= WrongNameSpace;
			result = std::max( result, Warning );
			break;
		case Exception::IssuerNameSpaceWarning:
			m_warning |= WrongNameSpace;
			result = std::max( result, Warning );
			break;
		case Exception::ProducedATLateWarning:
			result = std::max( result, Warning );
			break;
		case Exception::CertificateIssuerMissing:
		case Exception::CertificateUnknown:
		case Exception::OCSPResponderMissing:
		case Exception::OCSPCertMissing:
			result = std::max( result, Unknown );
			break;
		default:
			result = std::max( result, Invalid );
		}
		parseException( result, child );
	}
}

QString DigiDocSignature::policy() const
{
	return from(s->policy());
}

QString DigiDocSignature::profile() const
{
	return from(s->profile());
}

QString DigiDocSignature::role() const
{
	QStringList r = roles();
	r.removeAll( "" );
	return r.join( " / " );
}

QStringList DigiDocSignature::roles() const
{
	QStringList list;
	Q_FOREACH( const std::string &role, s->signerRoles() )
		list << from( role ).trimmed();
	return list;
}

void DigiDocSignature::setLastError( const Exception &e ) const
{
	QStringList causes;
	Exception::ExceptionCode code = Exception::General;
	int ddocError = -1;
	DigiDoc::parseException( e, causes, code, ddocError );
	m_lastError = causes.join( "\n" );
	m_lastErrorCode = ddocError;
}

QString DigiDocSignature::signatureMethod() const
{ return from( s->signatureMethod() ); }

QDateTime DigiDocSignature::signTime() const
{
	QString dateTime = from( s->claimedSigningTime() );
	if( dateTime.isEmpty() )
		return QDateTime();
	QDateTime date = QDateTime::fromString( dateTime, "yyyy-MM-dd'T'hh:mm:ss'Z'" );
	date.setTimeSpec( Qt::UTC );
	return date;
}

QString DigiDocSignature::spuri() const
{
	return from(s->SPUri());
}

QSslCertificate DigiDocSignature::tsCert() const
{
	return QSslCertificate(
		fromVector(s->TimeStampCertificate()), QSsl::Der );
}

QDateTime DigiDocSignature::tsTime() const
{
	QString dateTime = from( s->TimeStampTime() );
	if( dateTime.isEmpty() )
		return QDateTime();
	QDateTime date = QDateTime::fromString( dateTime, "yyyy-MM-dd'T'hh:mm:ss'Z'" );
	date.setTimeSpec( Qt::UTC );
	return date;
}

QSslCertificate DigiDocSignature::tsaCert() const
{
	return QSslCertificate(
		fromVector(s->ArchiveTimeStampCertificate()), QSsl::Der );
}

QDateTime DigiDocSignature::tsaTime() const
{
	QString dateTime = from( s->ArchiveTimeStampTime() );
	if( dateTime.isEmpty() )
		return QDateTime();
	QDateTime date = QDateTime::fromString( dateTime, "yyyy-MM-dd'T'hh:mm:ss'Z'" );
	date.setTimeSpec( Qt::UTC );
	return date;
}

DigiDocSignature::SignatureStatus DigiDocSignature::validate() const
{
	DigiDocSignature::SignatureStatus result = Valid;
	m_warning = 0;
	try
	{
		qApp->waitForTSL( m_parent->fileName() );
		s->validate();
	}
	catch( const Exception &e )
	{
		parseException( result, e );
		setLastError( e );
	}
	switch( result )
	{
	case Unknown:
	case Invalid: return result;
	default:
		if( SslCertificate( cert() ).type() & SslCertificate::TestType ||
			SslCertificate( ocspCert() ).type() & SslCertificate::TestType )
			return Test;

		return result;
	}
}

int DigiDocSignature::warning() const
{
	return m_warning;
}



QDocWorker::QDocWorker( const WorkData &workData )
:   operation( workData.operation )
,   owner( nullptr )
,   stopped( false )
,   taskId( workData.taskId )
,   taskResult( new TaskResult )
{
	taskResult->file = workData.file;
}

void QDocWorker::cancel()
{
	stopped = true;
}

bool QDocWorker::isBackgroundTask() const
{
	return owner != nullptr;
}

bool QDocWorker::isStopped() const
{
	return stopped;
}

int QDocWorker::getTaskId() const
{
	return taskId;
}

QDocWorker::TaskResult* QDocWorker::getTaskResult()
{
	return taskResult.get();
}

// Release worker result if task is successful
QDocWorker::TaskResult* QDocWorker::releaseTaskResult()
{
	TaskResult *data = nullptr;
	if( taskResult->success )
	{
		data = taskResult.release();
		if( isBackgroundTask() )
		{
			// Release thread
			Q_EMIT workFinished();
		}
	}

	return data;
}

void QDocWorker::run()
{
	bool success = operation( this );

	Q_EMIT complete( taskId, success );

	// If running in background and abandoned, delete worker automatically on thread close
	if( isBackgroundTask() && !success )
	{
		connect( owner, SIGNAL(finished()), this, SLOT(deleteLater()) );
		Q_EMIT workFinished();
	}
}

void QDocWorker::runInThread(QThread *thread)
{
	owner = thread;
	this->moveToThread(owner);
}



DigiDoc::DigiDoc( QObject *parent )
:	QObject( parent )
,	b(nullptr)
,	m_documentModel( new DocumentModel( this ) )
,   wid ( LastAction )
,   worker ( nullptr )
{}

DigiDoc::~DigiDoc() { clear(); }

void DigiDoc::addFile( const QString &file )
{
	if( !checkDoc( b->signatures().size() > 0, tr("Cannot add files to signed container") ) )
		return;

	QDocWorker::WorkData workData;
	workData.operation = [this]( QDocWorker *w ) { return this->addOperation(w); };
	workData.file = file;
	workData.isCancellable = false;
	workData.taskId = wid++;
	workData.title = tr( "Adding a file to container" );

	runWorker( workData, SIGNAL(added(int,bool)) );
}

bool DigiDoc::addOperation( QDocWorker *w )
{
	bool success = false;
	QDocWorker::TaskResult *result = w->getTaskResult();
	const QString file = result->file;

	Q_EMIT signalProgress( WorkProgressed );
	try
	{
		b->addDataFile(to(file), "application/octet-stream");
		success = true;
		Q_EMIT signalProgress( Processed );
	}
	catch( const Exception &e )
	{
		sendLastError(tr("Failed add file to container"), e, w);
		Q_EMIT progressFinished();
	}
	result->success = success;

	return success;
}

// Take ownership of operation result
QDocWorker::TaskResult* DigiDoc::addReleaseTask(int taskId)
{
	auto result = releaseTask( taskId );
	if( result != nullptr )
	{
		m_documentModel->reset();
	}

	return result;
}

bool DigiDoc::addSignature( const QByteArray &signature )
{
	if( !checkDoc( b->dataFiles().size() == 0, tr("Cannot add signature to empty container") ) )
		return false;

	bool result = false;
	try
	{
		b->addAdESSignature( std::vector<unsigned char>( signature.constData(), signature.constData() + signature.size() ) );
		result = true;
	}
	catch( const Exception &e ) { setLastError( tr("Failed to sign container"), e ); }
	return result;
}

void DigiDoc::cancel()
{
	if ( worker != nullptr )
	{
		worker->cancel();
	}
}

bool DigiDoc::checkDoc( bool status, const QString &msg ) const
{
	if( isNull() )
		qApp->showWarning( tr("Container is not open") );
	else if( status )
		qApp->showWarning( msg );
	return !isNull() && !status;
}

void DigiDoc::clear()
{
	delete b;
	b = nullptr;
	m_fileName.clear();
	m_documentModel->reset();
	for(const QString &file: m_tempFiles)
		QFile::remove(file);
	m_tempFiles.clear();
}

void DigiDoc::create( const QString &file )
{
	clear();
	b = Container::create( to( file ) );
	m_fileName = file;
	m_documentModel->reset();
}

DocumentModel* DigiDoc::documentModel() const { return m_documentModel; }

QString DigiDoc::fileName() const { return m_fileName; }

bool DigiDoc::isProgressActivated( const QString &fileName, const QString &msg, bool cancellable )
{
	// l00mb
	const int limit = 100 * 1024 * 1024;
	bool activated = false;
	auto containerSize = QFileInfo( fileName ).size();

	if( containerSize == 0 && !isNull() )
	{
		for(const DataFile *d: b->dataFiles())
		{
			containerSize += d->fileSize();
		}
	}

	if( containerSize >= limit )
	{
		Q_EMIT activateProgressDialog( fileName, msg, cancellable );
		activated = true;
	}

	return activated;
}

bool DigiDoc::isService() const
{
	return b->mediaType() == "application/pdf";
}
bool DigiDoc::isNull() const { return b == nullptr; }
bool DigiDoc::isReadOnlyTS() const
{
	return b->mediaType() == "application/vnd.etsi.asic-s+zip";
}
bool DigiDoc::isSupported() const
{
	return b->mediaType() == "application/vnd.etsi.asic-e+zip";
}

QString DigiDoc::mediaType() const
{ return b ? from( b->mediaType() ) : QString(); }

QString DigiDoc::newSignatureID() const
{
	QStringList list;
	for(const Signature *s: b->signatures())
		list << QString::fromUtf8(s->id().c_str());
	unsigned int id = 0;
	while(list.contains(QString("S%1").arg(id), Qt::CaseInsensitive)) ++id;
	return QString("S%1").arg(id);
}

void DigiDoc::open( const QString &file )
{
	qApp->waitForTSL( file );
	clear();

	QDocWorker::WorkData workData;
	workData.operation = [this]( QDocWorker *w ) { return this->openOperation(w);};
	workData.file = file;
	workData.isCancellable = true;
	workData.taskId = wid++;
	workData.title = tr( "Opening container" );

	runWorker( workData, SIGNAL(opened(int,bool)) );
}

bool DigiDoc::openOperation( QDocWorker *w )
{
	QDocWorker::TaskResult *result = w->getTaskResult();
	const QString file = result->file;
	bool success = false;

	try
	{
		auto cont = Container::open(to(file));
		result->container.reset( cont );
		if ( w->isStopped() )
		{
			result->success = false;
			return false;
		}
		Q_EMIT signalProgress( Working );

		if( result->container->mediaType() == "application/pdf" )
		{
			Q_EMIT w->verifyExternally();
		}
		else
		{
			Q_EMIT w->signalProgress( WorkProgressed );
		}
		success = true;
	}
	catch( const Exception &e )
	{ 
		Q_EMIT progressFinished();
		result->success = false;
		sendLastError(tr("An error occurred while opening the document."), e, w);
	}

	if( success )
	{
		auto checkedSignatures = signatures(result->container.get());
		if( checkedSignatures.size() > 0 )
		{
			double progress = WorkProgressed;
			double step = (Processed - progress) / (double)checkedSignatures.size();

			Q_FOREACH(const DigiDocSignature &c, checkedSignatures)
			{
				if ( w->isStopped() )
				{
					result->success = false;
					return false;
				}
				result->validationResults.append( c.validate() );
				result->warning |= c.warning();

				Q_EMIT w->signalProgress( round(progress += step) );
			}
		}
	}

	Q_EMIT w->signalProgress( Processed );

	return success;
}

// Take ownership of operation result
QDocWorker::TaskResult* DigiDoc::openReleaseTask(int taskId)
{
	auto result = releaseTask( taskId );
	if( result != nullptr )
	{
		m_fileName = result->file;
		m_documentModel->reset();
		b = result->container.release();
	}
	
	return result;
}

bool DigiDoc::parseException( const Exception &e, QStringList &causes,
	Exception::ExceptionCode &code, int &ddocError )
{
	causes << QString( "%1:%2 %3").arg( QFileInfo(from(e.file())).fileName() ).arg( e.line() ).arg( from(e.msg()) );
	if( e.code() & Exception::DDocError )
		ddocError = e.code() & ~Exception::DDocError;
	switch( e.code() )
	{
	case Exception::CertificateRevoked:
	case Exception::CertificateUnknown:
	case Exception::OCSPTimeSlot:
	case Exception::OCSPRequestUnauthorized:
	case Exception::PINCanceled:
	case Exception::PINFailed:
	case Exception::PINIncorrect:
	case Exception::PINLocked:
		code = e.code();
	default: break;
	}
	Q_FOREACH( const Exception &c, e.causes() )
		if( !parseException( c, causes, code, ddocError ) )
			return false;
	return true;
}

// Release ownership of result if not abandoned task
QDocWorker::TaskResult* DigiDoc::releaseTask(int taskId)
{
	QDocWorker::TaskResult *result = nullptr;

	if( worker != nullptr && worker->getTaskId() == taskId )
	{
		result = worker->releaseTaskResult();

		// Release successfully finished worker if running in background thread
		if( result && worker->isBackgroundTask() )
		{
			delete worker;
			worker = nullptr;
		}
	}

	return result;
}

void DigiDoc::removeSignature( unsigned int num )
{
	if( !checkDoc( num >= b->signatures().size(), tr("Missing signature") ) )
		return;
	try { b->removeSignature( num ); }
	catch( const Exception &e ) { setLastError( tr("Failed remove signature from container"), e ); }
}

void DigiDoc::runWorker( const QDocWorker::WorkData &workData, const char *completionSlot )
{
	worker = new QDocWorker( workData );

	const bool runInBackground = isProgressActivated( workData.file, workData.title, workData.isCancellable );
	Q_EMIT signalProgress( Starting );

	// Forward worker state signals
	connect( worker, SIGNAL(error(const QString&,const QString&,int,int)),
			this, SLOT(showLastError(const QString&,const QString&,int,int)) );
	connect( worker, SIGNAL(progressFinished()), this, SIGNAL(progressFinished()) );
	connect( worker, SIGNAL(signalProgress(int)), this, SIGNAL(signalProgress(int)) );
	connect( worker, SIGNAL(verifyExternally()), this, SIGNAL(verifyExternally()) );
	connect( worker, SIGNAL(complete(int,bool)), this, completionSlot );

	// Only long-running operations are performed in a worker thread
	if( runInBackground )
	{
		QThread* thread = new QThread;
		thread->setObjectName("QDocWorker");
		worker->runInThread(thread);

		connect( thread, SIGNAL(started()), worker, SLOT(run()) );
		connect( worker, SIGNAL(workFinished()), thread, SLOT(quit()) );

		// Delete thread automatically when work is done or application about to quit
		connect( thread, SIGNAL(finished()), thread, SLOT(deleteLater()) );

		connect( qApp, SIGNAL(aboutToQuit()), worker, SLOT(cancel()) );
		connect( qApp, SIGNAL(aboutToQuit()), worker, SLOT(deleteLater()) );
		connect( qApp, SIGNAL(aboutToQuit()), thread, SLOT(deleteLater()) );

		thread->start();
	}
	else
	{
		worker->run();
		delete worker;
		worker = nullptr;
	}
}

void DigiDoc::save( const QString &filename, SaveAction action )
{
	if( !filename.isEmpty() )
		m_fileName = filename;

	QDocWorker::WorkData workData;
	workData.operation = [this]( QDocWorker *w ) { return this->saveOperation(w);};
	workData.file = m_fileName;
	workData.isCancellable = false;
	workData.taskId = action;
	workData.title = tr( "Saving container" );

	runWorker( workData, SIGNAL(saved(int,bool)) );
}

bool DigiDoc::saveOperation( QDocWorker *w )
{
	bool success = false;
	QDocWorker::TaskResult *result = w->getTaskResult();
	const QString file = result->file;

	Q_EMIT signalProgress( Working );

	try
	{
		if( b != nullptr )
		{
			b->save( to(file) );
		}

		success = true;
		Q_EMIT signalProgress( Processed );
	}
	catch( const Exception &e )
	{
		Q_EMIT progressFinished();
		sendLastError(tr("Failed to save container"), e, w);
	}
	result->success = success;

	return success;
}

void DigiDoc::sendLastError( const QString &msg, const Exception &e, QDocWorker *w )
{
	QStringList causes;
	Exception::ExceptionCode code = Exception::General;
	int ddocError = -1;
	parseException( e, causes, code, ddocError );
	Q_EMIT w->error( msg, causes.join("\n"), code, ddocError );
}

void DigiDoc::setLastError( const QString &msg, const Exception &e )
{
	QStringList causes;
	Exception::ExceptionCode code = Exception::General;
	int ddocError = -1;
	parseException( e, causes, code, ddocError );
	showLastError( msg, causes.join("\n"), code, ddocError );
}

void DigiDoc::showLastError( const QString &msg, const QString &causes, int code, int ddocError )
{
	switch( code )
	{
	case Exception::CertificateRevoked:
		qApp->showWarning( tr("Certificate status revoked"), ddocError, causes ); break;
	case Exception::CertificateUnknown:
		qApp->showWarning( tr("Certificate status unknown"), ddocError, causes ); break;
	case Exception::OCSPTimeSlot:
		qApp->showWarning( tr("Check your computer time"), ddocError, causes ); break;
	case Exception::OCSPRequestUnauthorized:
		qApp->showWarning( tr("You have not granted IP-based access. "
			"Check the settings of your server access certificate."), ddocError, causes ); break;
	case Exception::PINCanceled:
		break;
	case Exception::PINFailed:
		qApp->showWarning( tr("PIN Login failed"), ddocError, causes ); break;
	case Exception::PINIncorrect:
		qApp->showWarning( tr("PIN Incorrect"), ddocError, causes ); break;
	case Exception::PINLocked:
		qApp->showWarning( tr("PIN Locked. Please use ID-card utility for PIN opening!"), ddocError, causes ); break;
	default:
		qApp->showWarning( msg, ddocError, causes ); break;
	}
}

bool DigiDoc::sign( const QString &city, const QString &state, const QString &zip,
	const QString &country, const QString &role, const QString &role2 )
{
	if( !checkDoc( b->dataFiles().size() == 0, tr("Cannot add signature to empty container") ) )
		return false;

	try
	{
		qApp->signer()->setSignatureProductionPlace(
			to(city), to(state), to(zip), to(country) );
		std::vector<std::string> roles;
		if( !role.isEmpty() || !role2.isEmpty() )
			roles.push_back( to((QStringList() << role << role2).join(" / ")) );
		qApp->signer()->setSignerRoles( roles );
		qApp->signer()->setProfile( signatureFormat() == "LT" ? "time-stamp" : "time-mark" );
		qApp->waitForTSL( fileName() );
		b->sign( qApp->signer() );
		return true;
	}
	catch( const Exception &e )
	{
		QStringList causes;
		Exception::ExceptionCode code = Exception::General;
		int ddocError = -1;
		parseException( e, causes, code, ddocError );
		if( code == Exception::PINIncorrect )
		{
			qApp->showWarning( tr("PIN Incorrect") );
			if( !(qApp->signer()->tokensign().flags() & TokenData::PinLocked) )
				return sign( city, state, zip, country, role, role2 );
		}
		else
			setLastError( tr("Failed to sign container"), e );
	}
	return false;
}

QString DigiDoc::signatureFormat() const
{
	if(m_fileName.endsWith("ddoc", Qt::CaseInsensitive))
		return "LT_TM";

	QString def = Settings(qApp->applicationName()).value( "type", "bdoc" ).toString() == "asice" ? "LT" : "LT_TM";
	switch(b->signatures().size())
	{
	case 0:
		if( QStringList({"asice", "sce"}).contains(QFileInfo(m_fileName).suffix(), Qt::CaseInsensitive) )
			return "LT";
		return def;
	case 1:
		return b->signatures()[0]->profile().find("time-stamp") != std::string::npos ? "LT" : "LT_TM";
	default: break;
	}
	Signature *sig = nullptr;
	for(Signature *s: b->signatures())
	{
		if(!sig)
			sig = s;
		else if(sig->profile() != s->profile())
			return def;
	}
	return sig->profile().find("time-stamp") != std::string::npos ? "LT" : "LT_TM";
}

QList<DigiDocSignature> DigiDoc::signatures()
{
	return signatures(b);
}

QList<DigiDocSignature> DigiDoc::signatures(Container* c)
{
	QList<DigiDocSignature> list;
	if( c == nullptr )
		return list;
	try
	{
		for(const Signature *signature: c->signatures())
			list << DigiDocSignature(signature, this);
	}
	catch( const Exception &e ) { setLastError( tr("Failed to get signatures"), e ); }
	return list;
}

DigiDoc::DocumentType DigiDoc::documentType() const
{
	return checkDoc() && b->mediaType() == "application/vnd.etsi.asic-e+zip" ? BDoc2Type : DDocType;
}

QByteArray DigiDoc::getFileDigest( unsigned int i ) const
{
	if( !checkDoc() || i >= b->dataFiles().size() )
		return QByteArray();

	try
	{
		const DataFile *file = b->dataFiles().at( i );
		return fromVector(file->calcDigest("http://www.w3.org/2001/04/xmlenc#sha256"));
	}
	catch( const Exception & ) {}

	return QByteArray();
}
