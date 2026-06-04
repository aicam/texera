package org.apache.amber.operator.cloudmapper

import com.fasterxml.jackson.annotation.{JsonProperty, JsonPropertyDescription}
import com.kjetland.jackson.jsonSchema.annotations.JsonSchemaTitle
import org.apache.texera.amber.core.tuple.{Attribute, AttributeType, Schema}
import org.apache.texera.amber.core.workflow.{OutputPort, PortIdentity}
import org.apache.texera.amber.operator.metadata.{OperatorGroupConstants, OperatorInfo}
import org.apache.texera.amber.operator.source.PythonSourceOperatorDescriptor
import org.apache.texera.amber.core.storage.FileResolver
import org.apache.texera.amber.core.storage.util.LakeFSStorageClient
import org.apache.texera.amber.config.ApplicationConfig

import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.nio.file.Paths
import scala.jdk.CollectionConverters._

class CloudMapperSourceOpDesc extends PythonSourceOperatorDescriptor {
  @JsonProperty(required = true)
  @JsonSchemaTitle("FastQ Dataset")
  @JsonPropertyDescription("Dataset containing fastq files")
  val directoryName: String = ""

  @JsonProperty(required = true)
  var referenceGenome: ReferenceGenome = _

  @JsonProperty(required = false)
  @JsonSchemaTitle("Additional Reference Genomes")
  @JsonPropertyDescription("Add one or more additional reference genomes (optional)")
  var additionalReferenceGenomes: List[ReferenceGenome] = List()

  @JsonProperty(required = true)
  @JsonSchemaTitle("Cluster")
  @JsonPropertyDescription("Cluster")
  val cluster: String = ""

  // Resolved at codegen from `cluster-launcher-service.target`
  // (env: CLUSTER_LAUNCHER_SERVICE_TARGET). Shared with ClusterServiceClient
  // so REST + operator always point at the same Go service.
  private val clusterLauncherServiceTarget: String =
    ApplicationConfig.clusterLauncherServiceTarget.stripSuffix("/")

  // Getter to retrieve only the id part (cid) from the cluster
  def clusterId: String = {
    if (cluster.startsWith("#")) {
      cluster.split(" ")(0).substring(1) // Extracts the cid part by splitting and removing '#'
    } else {
      ""
    }
  }

  // Render a Python string literal safely.
  private def pyStr(s: String): String =
    "'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'"

  override def generatePythonCode(): String = {
    // Resolve dataset references at codegen WITHOUT materializing files locally. Compilation
    // was offloaded off the computing unit, so this codegen now runs in the compiling-service
    // pod, which does NOT share a filesystem with the CU that executes this UDF. We therefore
    // emit the dataset *paths* and let the CU download each file itself at runtime via
    // DatasetFileDocument (LakeFS presigned URLs), the same way every other source operator reads.
    val directoryUri = FileResolver.resolveDirectory(directoryName)
    val dirSegments =
      Paths.get(directoryUri.getPath).iterator().asScala.map(_.toString).toArray
    val readsRepo = dirSegments(0)
    val readsVersionHash = URLDecoder.decode(dirSegments(1), StandardCharsets.UTF_8.name())
    val datasetPathPrefix = directoryName.stripPrefix("/").stripSuffix("/")

    // List the reads version's object paths (LakeFS; the backend has direct access at codegen).
    val readsObjectPaths = LakeFSStorageClient
      .retrieveObjectsOfVersion(readsRepo, readsVersionHash)
      .map(_.getPath)
      .filter(p => p != null && p.nonEmpty)

    // (zipEntryPath, DatasetFileDocument path) tuples that the CU resolves + downloads at runtime.
    val pythonReadsFiles = readsObjectPaths
      .map(p => s"(${pyStr(p)}, ${pyStr(s"$datasetPathPrefix/$p")})")
      .mkString("[", ", ", "]")

    // Convert the Scala referenceGenome to a Python string
    val pythonReferenceGenome = s"'${referenceGenome.referenceGenome.getName}'"

    // Convert the Scala additionalReferenceGenomes list to a Python list format
    val pythonAdditionalReferenceGenomes = additionalReferenceGenomes
      .map(_.referenceGenome.getName)
      .map(name => s"'$name'")
      .mkString("[", ", ", "]")

    // Combine main reference genome with additional ones
    val pythonAllReferenceGenomes =
      s"[${pythonReferenceGenome}] + ${pythonAdditionalReferenceGenomes}"

    // FASTA / GTF single files (custom 'My Reference'): read at runtime in the CU as file-like
    // BytesIO objects via DatasetFileDocument, instead of opening a compile-time local path.
    val pythonFastaFiles = (referenceGenome :: additionalReferenceGenomes)
      .flatMap(_.fastAFiles)
      .map(file => s"DatasetFileDocument(${pyStr(file)}).read_file()")
      .mkString("[", ", ", "]")

    val pythonGtfFileValue = (referenceGenome :: additionalReferenceGenomes)
      .find(_.referenceGenome == ReferenceGenomeEnum.MY_REFERENCE)
      .flatMap(_.gtfFile)
      .map(file => s"DatasetFileDocument(${pyStr(file)}).read_file()")
      .getOrElse("None")

    s"""from pytexera import *
       |
       |class GenerateOperator(UDFSourceOperator):
       |
       |    @overrides
       |    def produce(self) -> Iterator[Union[TupleLike, TableLike, None]]:
       |        import requests, time, tarfile, io, os, tempfile, zipfile
       |
       |        service_url = "${clusterLauncherServiceTarget}"
       |        cluster_id  = ${clusterId}
       |
       |        # ------------------------------------------------------------------
       |        # Step 0: Build the reads zip from the dataset version AT RUNTIME in
       |        # this computing-unit pod. Each file is fetched from LakeFS via a
       |        # presigned URL (DatasetFileDocument), then written into a local zip.
       |        # The CU compiles nothing, so the path must be created here, not baked
       |        # in by the (separate) compiling-service pod.
       |        # ------------------------------------------------------------------
       |        reads_files = ${pythonReadsFiles}
       |        reads_fd, reads_path = tempfile.mkstemp(suffix=".zip")
       |        os.close(reads_fd)
       |        with zipfile.ZipFile(reads_path, 'w', zipfile.ZIP_DEFLATED) as zf:
       |            for zip_entry, dataset_path in reads_files:
       |                zf.writestr(zip_entry, DatasetFileDocument(dataset_path).read_file().read())
       |
       |        # ------------------------------------------------------------------
       |        # Step 1: Ask the Go service for a presigned S3 PUT URL.
       |        # The reads zip will be sent directly to S3 from here — the Go
       |        # service is not in the data path for the large file.
       |        # ------------------------------------------------------------------
       |        upload_meta_resp = requests.post(f"{service_url}/api/job/request-upload")
       |        upload_meta_resp.raise_for_status()
       |        upload_meta = upload_meta_resp.json()
       |        upload_url = upload_meta["upload_url"]
       |        s3_key     = upload_meta["s3_key"]
       |        job_id     = upload_meta["job_id"]
       |
       |        yield  # let Texera heartbeat while we upload
       |
       |        # ------------------------------------------------------------------
       |        # Step 2: PUT the reads zip directly to S3 (presigned URL, no proxy).
       |        # ------------------------------------------------------------------
       |        with open(reads_path, 'rb') as reads_file:
       |            put_resp = requests.put(upload_url, data=reads_file)
       |        put_resp.raise_for_status()
       |
       |        yield  # let Texera heartbeat while we notify
       |
       |        # ------------------------------------------------------------------
       |        # Step 3: Notify the Go service to start the job. Pass s3_key and
       |        # job_id so it knows which S3 object to pull on the EC2 head node.
       |        # FASTA/GTF files (small, annotation-only) still go as multipart.
       |        # ------------------------------------------------------------------
       |        selected_genomes = ${pythonAllReferenceGenomes}
       |        form_data = {
       |            'cid':    str(cluster_id),
       |            's3_key': s3_key,
       |            'job_id': str(job_id),
       |        }
       |        for index, genome in enumerate(selected_genomes):
       |            form_data[f'referenceGenome[{index}]'] = genome
       |
       |        files = {}
       |        if 'My Reference' in selected_genomes:
       |            fasta_files = ${pythonFastaFiles}
       |            for index, fasta_file in enumerate(fasta_files):
       |                files[f'fastaFiles[{index}]'] = fasta_file
       |            gtf_file = ${pythonGtfFileValue}
       |            if gtf_file is not None:
       |                files['gtfFile'] = gtf_file
       |
       |        response = requests.post(f"{service_url}/api/job/create",
       |                                 data=form_data, files=files if files else None)
       |        response.raise_for_status()
       |
       |        # ------------------------------------------------------------------
       |        # Step 4: Poll until the job is finished.
       |        # ------------------------------------------------------------------
       |        while True:
       |            status_response = requests.get(f'{service_url}/api/job/status/{job_id}')
       |            status = status_response.json().get("status")
       |
       |            if status == "finished":
       |                print("Job finished! Downloading the result...")
       |                break
       |            elif status == "failed":
       |                print("Job failed.")
       |                yield {
       |                    'Sample': None,
       |                    'features.tsv.gz': None,
       |                    'barcodes.tsv.gz': None,
       |                    'matrix.mtx.gz': None
       |                }
       |                return
       |
       |            print("Job is still processing...")
       |            time.sleep(0.5)
       |            yield
       |
       |        # ------------------------------------------------------------------
       |        # Step 5: Download results.
       |        # The server streams a tar.gz archive containing all filtered/
       |        # output files.  We parse it member-by-member so the operator
       |        # never holds the entire decompressed matrix in RAM at once.
       |        # ------------------------------------------------------------------
       |        download_response = requests.get(f'{service_url}/api/job/download/{job_id}',
       |                                         stream=True)
       |        download_response.raise_for_status()
       |
       |        # urllib3 raw socket; tell it to handle transport-encoding itself
       |        download_response.raw.decode_content = True
       |
       |        samples = {}
       |        with tarfile.open(fileobj=download_response.raw, mode='r|gz') as tar:
       |            for member in tar:
       |                if not member.isfile():
       |                    continue
       |                parts = member.name.split('/')
       |                # Expected layout: <SampleName>/filtered/<file>.gz
       |                if len(parts) < 3:
       |                    continue
       |                sample_name = parts[0]
       |                fname = parts[-1]
       |                if fname in ('features.tsv.gz', 'barcodes.tsv.gz', 'matrix.mtx.gz'):
       |                    f = tar.extractfile(member)
       |                    if f is not None:
       |                        samples.setdefault(sample_name, {})[fname] = f.read()
       |
       |        if not samples:
       |            print("Download succeeded but archive contained no recognised files.")
       |            yield {
       |                'Sample': None,
       |                'features.tsv.gz': None,
       |                'barcodes.tsv.gz': None,
       |                'matrix.mtx.gz': None
       |            }
       |            return
       |
       |        for sample_name, files in samples.items():
       |            yield {
       |                'Sample':          sample_name,
       |                'features.tsv.gz': files.get('features.tsv.gz'),
       |                'barcodes.tsv.gz': files.get('barcodes.tsv.gz'),
       |                'matrix.mtx.gz':   files.get('matrix.mtx.gz')
       |            }
    """.stripMargin
  }
  override def operatorInfo: OperatorInfo =
    OperatorInfo(
      "CloudBioMapper",
      "Running sequence alignment using public cluster services",
      OperatorGroupConstants.API_GROUP,
      inputPorts = List.empty,
      outputPorts = List(OutputPort())
    )
  override def asSource() = true
  override def sourceSchema(): Schema =
    Schema()
      .add(
        new Attribute("Sample", AttributeType.STRING),
        new Attribute("features.tsv.gz", AttributeType.BINARY),
        new Attribute("barcodes.tsv.gz", AttributeType.BINARY),
        new Attribute("matrix.mtx.gz", AttributeType.BINARY)
      )

  def getOutputSchemas(inputSchemas: Map[PortIdentity, Schema]): Map[PortIdentity, Schema] = {
    Map(operatorInfo.outputPorts.head.id -> sourceSchema())
  }
}
