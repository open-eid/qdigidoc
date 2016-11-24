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

#pragma once

#include <QtCore/QAbstractTableModel>

#include <digidocpp/Container.h>
#include <digidocpp/Exception.h>

#include <functional>
#include <memory>

class DigiDoc;
class QDateTime;
class QSslCertificate;
class QStringList;

class DocumentModel: public QAbstractTableModel
{
	Q_OBJECT
public:
	enum Columns
	{
		Name = 0,
		Mime = 1,
		Size = 2,
		Save = 3,
		Remove = 4,
		Id = 5,

		NColumns
	};

	int columnCount( const QModelIndex &parent = QModelIndex() ) const;
	QVariant data( const QModelIndex &index, int role = Qt::DisplayRole ) const;
	Qt::ItemFlags flags( const QModelIndex &index ) const;
	QMimeData *mimeData( const QModelIndexList &indexes ) const;
	QStringList mimeTypes() const;
	bool removeRows( int row, int count, const QModelIndex &parent = QModelIndex() );
	int rowCount( const QModelIndex &parent = QModelIndex() ) const;
	Qt::DropActions supportedDragActions() const;

	void reset();
	QString save( const QModelIndex &index, const QString &path ) const;

public slots:
	void open( const QModelIndex &index );

private:
	DocumentModel( DigiDoc *doc );
	Q_DISABLE_COPY(DocumentModel)

	DigiDoc *d;

	friend class DigiDoc;
};

class DigiDocSignature
{
public:
	enum SignatureStatus
	{
		Valid,
		Warning,
		Test,
		Invalid,
		Unknown
	};
	enum SignatureWarning
	{
		WrongNameSpace = 1 << 1,
		DigestWeak = 1 << 2
	};
	DigiDocSignature( const digidoc::Signature *signature, DigiDoc *parent );

	QSslCertificate	cert() const;
	QDateTime	dateTime() const;
	QString		lastError() const;
	int			lastErrorCode() const;
	QString		location() const;
	QStringList	locations() const;
	QSslCertificate ocspCert() const;
	QByteArray	ocspNonce() const;
	QDateTime	ocspTime() const;
	DigiDoc		*parent() const;
	QString		policy() const;
	QString		profile() const;
	QString		role() const;
	QStringList	roles() const;
	QString		signatureMethod() const;
	QDateTime	signTime() const;
	QString		spuri() const;
	QSslCertificate tsCert() const;
	QDateTime	tsTime() const;
	QSslCertificate tsaCert() const;
	QDateTime	tsaTime() const;
	SignatureStatus validate() const;
	int warning() const;

private:
	void setLastError( const digidoc::Exception &e ) const;
	void parseException( SignatureStatus &result, const digidoc::Exception &e ) const;

	const digidoc::Signature *s;
	mutable QString m_lastError;
	mutable int m_lastErrorCode;
	DigiDoc *m_parent;
	mutable unsigned int m_warning;
};

class QDocWorker: public QObject
{
	Q_OBJECT

public:
	struct WorkData {
		int taskId;
		QString file;
		QString title;
		bool isCancellable;
		std::function<bool(QDocWorker*)> operation;
	};

	struct TaskResult {
		std::unique_ptr<digidoc::Container> container = nullptr;
		QString file;
		QList<DigiDocSignature::SignatureStatus> validationResults;
		bool success = true;
		int warning = 0;
	};

	explicit QDocWorker( const WorkData &workData );

	bool isBackgroundTask() const;
	bool isStopped() const;
	TaskResult* getTaskResult();
	int getTaskId() const;
	TaskResult* releaseTaskResult();
	void runInThread(QThread *thread);

Q_SIGNALS:
	void progressFinished();
	void complete( int, bool );
	void signalProgress( int );
	void verifyExternally();
	void workFinished();
	void error( const QString&,const QString&,int,int );

public Q_SLOTS:
	void cancel();
	void run();

private:
	std::function<bool(QDocWorker*)> operation;
	QThread *owner;
	volatile bool stopped;
	int taskId;
	std::unique_ptr<TaskResult> taskResult;
};

class DigiDoc: public QObject
{
	Q_OBJECT
public:
	enum DocumentType {
		DDocType,
		BDoc2Type
	};
	enum SaveAction {
		NoAction,
		ViewAction,
		SignAction,
		SignAndViewAction,
		LastAction
	};
	enum OperationProgress {
		Initial = 5,
		Starting = 10,
		Working = 25,
		WorkProgressed = 40,
		Processed = 80,
		Finished = 100
	};

	explicit DigiDoc( QObject *parent = 0 );
	~DigiDoc();

	void addFile( const QString &file );
	QDocWorker::TaskResult* addReleaseTask(int taskId);
	bool addSignature( const QByteArray &signature );
	void create( const QString &file );
	void clear();
	DocumentModel *documentModel() const;
	QString fileName() const;
	bool isNull() const;
	bool isProgressActivated( const QString &fileName, const QString &msg, bool cancellable );
	bool isReadOnlyTS() const;
	bool isService() const;
	bool isSupported() const;
	QString mediaType() const;
	QString newSignatureID() const;
	void open( const QString &file );
	QDocWorker::TaskResult* openReleaseTask( int taskId );
	QDocWorker::TaskResult* releaseTask( int taskId );
	void removeSignature( unsigned int num );
	void save( const QString &filename = QString(), SaveAction action = ViewAction );
	bool sign(
		const QString &city,
		const QString &state,
		const QString &zip,
		const QString &country,
		const QString &role,
		const QString &role2 );
	QString signatureFormat() const;
	QList<DigiDocSignature> signatures();
	DocumentType documentType() const;
	QByteArray getFileDigest( unsigned int i ) const;

	static bool parseException( const digidoc::Exception &e, QStringList &causes,
		digidoc::Exception::ExceptionCode &code, int &ddocError );

private:
	bool addOperation( QDocWorker *w );
	bool checkDoc( bool status = false, const QString &msg = QString() ) const;
	bool openOperation( QDocWorker *worker );
	void runWorker( const QDocWorker::WorkData &workData, const char *completionSlot );
	bool saveOperation( QDocWorker *worker );
	void sendLastError( const QString &msg, const digidoc::Exception &e, QDocWorker *w );
	void setLastError( const QString &msg, const digidoc::Exception &e );
	QList<DigiDocSignature> signatures(digidoc::Container* c);

	digidoc::Container *b;
	QString			m_fileName;
	DocumentModel	*m_documentModel;
	QStringList		m_tempFiles;
	int			 	wid;
	QDocWorker*	 	worker;

public Q_SLOTS:
	void cancel();
	void showLastError( const QString &msg, const QString &causes, int code, int ddocError );

Q_SIGNALS:
	void activateProgressDialog( const QString&,const QString&,bool );
	void added( int,bool );
	void opened( int,bool );
	void progressFinished();
	void saved( int,bool );
	void signalProgress( int );
	void verifyExternally();

	friend class DocumentModel;
};
